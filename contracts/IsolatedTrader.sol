// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

// utils
import {Ownable2StepUpgradeable} from '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {BaseRelayRecipient} from './utils/BaseRelayRecipient.sol';
import {BlockContext} from './utils/BlockContext.sol';
import {IsolatedTraderBase} from './IsolatedTraderBase.sol';

// interfaces
import {IPerpetual} from './interfaces/IPerpetual.sol';
import {ITrader} from './interfaces/ITrader.sol';
import {IEvaluator} from './interfaces/IEvaluator.sol';
import {IMarginBank} from './interfaces/IMarginBank.sol';

// maths
import {BaseMath} from './maths/BaseMath.sol';
import {PositionBalanceMath} from './maths/PositionBalanceMath.sol';

// libraries
import {TypedSignature} from './libraries/TypedSignature.sol';
import {Types} from './libraries/Types.sol';
import {Require} from './libraries/Require.sol';

/**
 * @title Isolated Trader
 * @author MNX Markets <help@mnx.fi>
 * @notice Used to perform on-chain order cancellation and normal trade execution.
 * The trade() method on the contract is only invokable by the perpetual market.
 * A whitelisted settlement operator must invoke trade() on the perpetual to
 * execute a trade of two orders (maker/taker).
 * @dev The contract is made upgradable using openzeppelin upgrades-pluging, don't change
 * the order of variables. Read more: https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies
 */
contract IsolatedTrader is
  ITrader,
  IsolatedTraderBase,
  Ownable2StepUpgradeable,
  // OZ 5.6.1 is @custom:stateless and uses a fixed namespaced slot;
  // issue #32 tests pin these proxy-layout assumptions.
  ReentrancyGuard,
  BaseRelayRecipient,
  BlockContext
{
  using BaseMath for uint128;
  using BaseMath for int256;

  //
  // EVENTS
  //

  /// @notice Emitted when an order is cancelled
  event OrderCancel(
    address indexed maker,
    bytes32 orderHash,
    uint128 timestamp
  );

  /// @notice event emitted when order is filled
  event OrderFill(
    bytes32 orderHash,
    Order order,
    address sigMaker,
    Fill fill,
    uint128 newFilledQuantity,
    uint128 timestamp
  );

  /// @notice Emitted when a cancellation operator is updated.
  event CancellationOperatorUpdate(address account);

  /**
   * @notice Emitted when an order is cancelled by operator
   */
  event OrderCancelledByOperator(bytes32 orderHash, uint128 timestamp);

  event TraderWhitelisted(
    address account,
    bool status,
    uint128 makerFee,
    uint128 takerFee
  );

  //
  // ENUMS
  //
  enum OrderStatus {
    Open,
    Canceled
  }

  //
  // STRUCTS
  //

  struct OrderStatusQuery {
    OrderStatus status;
    uint128 filledAmount;
  }

  /// @dev Trade data expected by trade method of this contract
  struct TradeData {
    // Maker order
    Order orderA;
    // Taker Order
    Order orderB;
    // Fill describing the trade
    Fill fill;
    // Maker's signature for the maker order
    TypedSignature.Signature signatureA;
    // Taker's signature for the taker order
    TypedSignature.Signature signatureB;
  }

  /// @dev order object to be signed and submitted to perpetual contract in trade data
  struct Order {
    /// encoded order flags, isBuy, decreasOnly
    bytes8 flags;
    // quantity of asset to be traded
    uint128 quantity;
    // limit price (worst acceptable fill price); 0 signs a market order
    uint128 price;
    // stop order price
    uint128 triggerPrice;
    // Signed trigger direction (Types.TriggerCondition as uint8; audit #50).
    // Kept as uint8 so an out-of-range value fails per-order validation, naming
    // the maker ('P81'; 'P84' for a forced liquidation order), instead of an
    // empty, unattributed revert inside abi.decode. Values 3+ are reserved for
    // future authenticated mark-price variants; see Types.sol.
    uint8 triggerCondition;
    // leverage for trade, 1e18 fixed point; must be a whole multiple of 1e18 (5e18 = 5x)
    uint128 leverage;
    // address of order maker
    address maker;
    // time after which order becomes invalid
    uint128 expiration;
  }

  /// @dev struct with trade quantity and price
  struct Fill {
    // Fill amount being deducted from both orders' amount
    uint128 quantity;
    // Fill price, both orders must agree on
    uint128 price;
  }

  // intermediate variables computed during isolated margin application
  // used to prevent stack too deep issue
  struct IMVariables {
    uint128 oldQPos;
    uint128 closingFeePerUnit;
    uint128 pPos;
    uint128 marginPerUnit;
    int256 equityPerUnit;
    int256 pnlPerUnit;
    int256 fundsFlow;
    bool isBuy;
    bool isReduceOnly;
    bool isBinaryMarket;
  }

  struct IMResponse {
    Types.PositionBalance balance;
    int256 fundsFlow;
    int256 pnl;
    uint128 fee;
  }

  struct WhitelistedTrader {
    bool status;
    uint128 makerFee;
    uint128 takerFee;
  }

  //**********************************************************//
  //    The below state variables can not change the order    //
  //**********************************************************//

  //
  // EIP 712 Constants
  //

  /// @dev EIP712 Domain Name value
  string public constant EIP712_DOMAIN_NAME = 'IsolatedTrader';

  /// @dev EIP712 Domain Version value.
  /// Bumped from '1.0' to '2.0' by audit issue #50: version 2 adds the signed
  /// `triggerCondition` to the Order struct. The order typehash changes with
  /// the struct, so version-1 order signatures already fail to recover; the
  /// domain bump makes the cutover explicit and aligns the order domain with
  /// the '2.0' Perpetual authorization domain from audit issue #42 — one
  /// coordinated signature-version-2 maintenance window for both.
  /// Deployed proxies cache the domain hash at initialize, so the upgrade
  /// campaign must run `migrateOrderSigningDomainToV2()` in the same
  /// upgrade-and-call operation as the implementation swap.
  string public constant EIP712_DOMAIN_VERSION = '2.0';

  /// @dev Hash of the EIP712 Domain Separator Schema
  bytes32 public constant EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH =
    keccak256(
      abi.encodePacked(
        'EIP712Domain(',
        'string name,',
        'string version,',
        'uint256 chainId,',
        'address verifyingContract',
        ')'
      )
    );

  /// @dev Hash of the EIP712 Order struct type (signature version 2:
  /// `triggerCondition` added after `triggerPrice` by audit #50).
  bytes32 private constant EIP712_ORDER_STRUCT_SCHEMA_HASH =
    keccak256(
      abi.encodePacked(
        'Order(',
        'bytes8 flags,',
        'uint128 quantity,',
        'uint128 price,',
        'uint128 triggerPrice,',
        'uint8 triggerCondition,',
        'uint128 leverage,',
        'address maker,',
        'uint128 expiration',
        ')'
      )
    );

  /// @dev Trder flag 1 for this contract
  bytes32 public constant TRADER_ID = bytes32(uint256(1));

  /// @dev Per-fill flag returned for book-side forced liquidation fills.
  bytes32 public constant LIQUIDATION_TRADER_ID = bytes32(uint256(2));
  bytes32 public constant DUAL_LIQUIDATION_TRADER_ID = bytes32(uint256(4));

  /// @dev Hash of the EIP712 Domain Separator data
  bytes32 public _EIP712_DOMAIN_HASH_;

  /// @dev Bitmasks for the flags field
  bytes8 public constant FLAG_MASK_NULL = bytes8(0);
  bytes8 public constant FLAG_MASK_IS_BUY = bytes8(bytes32(uint256(1 << 192)));
  bytes8 public constant FLAG_MASK_IS_REDUCE_ONLY =
    bytes8(bytes32(uint256(1 << 193)));

  /// @notice address of the perpetual contract
  address public perpetual;

  /// @notice address of the evaluator contract
  address public evaluator;

  /// @notice packed order state: lower 128 bits = filled quantity, bit 128 = canceled flag
  mapping(bytes32 => uint256) public orderState;

  /// @notice address of whitelisted account able to cancel order just by their hash
  address public cancellationOperator;

  /// @dev Deprecated storage retained only to preserve the proxy layout.
  /// IsolatedTrader has never read this value. Do not reuse this slot or expose
  /// it as an authoritative dependency.
  address private marginBank;

  uint256[50] private __gap;

  /// @notice Whitelisted traders and their custom maker and taker fee rates. The
  /// trade path charges the lower of each custom rate and the current default.
  mapping(address => WhitelistedTrader) public whitelistedTraders;

  //**********************************************************//
  //    The above state variables can not change the order    //
  //**********************************************************//

  //◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤ add state variables below ◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤//

  //◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣ add state variables above ◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣//

  uint256 internal constant CANCELED_BIT = 1 << 128;
  uint128 internal constant FILLED_QTY_MASK = type(uint128).max;

  function _getFilledQuantity(
    bytes32 orderHash
  ) internal view returns (uint128) {
    return uint128(orderState[orderHash] & uint256(FILLED_QTY_MASK));
  }

  function _isCanceled(bytes32 orderHash) internal view returns (bool) {
    return (orderState[orderHash] & CANCELED_BIT) != 0;
  }

  function _setCanceled(bytes32 orderHash) internal {
    orderState[orderHash] = orderState[orderHash] | CANCELED_BIT;
  }

  function _setFilledQuantity(bytes32 orderHash, uint128 qty) internal {
    orderState[orderHash] =
      (orderState[orderHash] & ~uint256(FILLED_QTY_MASK)) |
      uint256(qty);
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  /**
   * Throws if called by any account other than the white listed account.
   */
  modifier onlyCancellationOperator() {
    /**
     * @dev using msgSender() instead of _msgSender(), as the methods
     * using onlyCancellationOperator modifier are gasless, can be invoked by
     * a trusted relayer
     */
    require(
      cancellationOperator == msgSender(),
      'IsolatedTrader: caller is not the cancellation operator'
    );
    _;
  }

  /**
   * @notice initializes the contract
   * @dev makes deployer of the contract default cancelaltion operator
   * @param _perpetual address of perpetual contract
   * @param _evelautor address of evaluator contract
   * @param  _trustedForwarder The ERC-2771 forwarder contract whose appended
   * sender `msgSender()` trusts; it must have deployed code
   * @param _chainId id of the chain, must equal the chain being deployed to
   */
  function initialize(
    address _perpetual,
    address _evelautor,
    address _trustedForwarder,
    uint256 _chainId
  ) public initializer {
    /**
     * @dev The EIP-712 domain hash is cached at initialization and there is
     * no routine setter; recomputing it takes a deliberate single-use
     * reinitializer (`migrateOrderSigningDomainToV2`, which derives the
     * chain id from `block.chainid` rather than trusting an argument).
     * Deploying with a chain id that is not the active chain would either
     * invalidate every order signed for this network, or - if the proxy
     * address is mirrored onto another chain - make orders signed for that
     * other domain valid here. Fail the deployment instead of leaning on a
     * later migration to repair it.
     */
    require(
      _chainId == block.chainid,
      'IsolatedTrader: Chain id must match the active chain'
    );

    perpetual = _perpetual;
    evaluator = _evelautor;

    _EIP712_DOMAIN_HASH_ = computeDomainHash(
      EIP712_DOMAIN_NAME,
      EIP712_DOMAIN_VERSION,
      _chainId,
      address(this)
    );

    cancellationOperator = _msgSender();

    __MetaTransaction_init(_trustedForwarder);
    __Ownable_init(_msgSender());
    __Ownable2Step_init();

    emit CancellationOperatorUpdate(cancellationOperator);
  }

  function setTrustedForwarder(address _trustedForwarder) external onlyOwner {
    _setTrustedForwarder(_trustedForwarder);
  }

  /**
   * @notice Recomputes the cached EIP-712 domain hash under domain version
   * '2.0' on an already-initialized proxy (audit #50 order-signature cutover).
   * @dev `initialize` caches `_EIP712_DOMAIN_HASH_` permanently, so a proxy
   * deployed under version '1.0' keeps the old domain across implementation
   * upgrades unless it is migrated. The upgrade campaign MUST call this in
   * the same atomic upgrade-and-call operation as the implementation swap:
   * between the swap and this migration, a version-2 struct signed against
   * the stale version-1 domain would still recover (harmless to third
   * parties — the maker signed that exact content — but a liveness /
   * misconfiguration hazard for honest clients already signing '2.0').
   *
   * Deterministic and argument-free on purpose (LiquidityVault migration
   * doctrine): every input is a constant, the chain id, or this proxy's own
   * address, so an external caller racing the campaign cannot steer the
   * result. Fresh deployments initialize directly at '2.0' and never need
   * this call.
   */
  function migrateOrderSigningDomainToV2() external reinitializer(2) {
    _EIP712_DOMAIN_HASH_ = computeDomainHash(
      EIP712_DOMAIN_NAME,
      EIP712_DOMAIN_VERSION,
      block.chainid,
      address(this)
    );
  }

  /**
   * @notice Allows a taker to match with a signed maker order, or two forced liquidation orders
   * @param  maker        Order maker
   * @param  taker        Order taker
   * @param  price        Current oracle price of asset
   * @param  data         Trade data struct (of type TradeData)
   * @return              TradeResult indicating the result of the trade
   */
  function trade(
    address maker,
    address taker,
    uint128 price,
    bytes calldata data,
    uint128 tradeTimestamp
  ) external override nonReentrant returns (Types.TradeResult memory) {
    require(
      _msgSender() == perpetual,
      'IsolatedTrader: Msg sender must be Perpetual'
    );

    TradeData memory tradeData = abi.decode(data, (TradeData));
    bytes32 orderAHash = _getOrderHash(tradeData.orderA);
    bytes32 orderBHash = _getOrderHash(tradeData.orderB);
    bool orderAForcedLiquidation = _isForcedLiquidation(tradeData.orderA);
    bool orderBForcedLiquidation = _isForcedLiquidation(tradeData.orderB);

    Require.that(
      !orderAForcedLiquidation || orderBForcedLiquidation,
      'IsolatedTrader: Forced maker requires forced taker',
      tradeData.orderA.maker
    );

    // Validate orders are open & have correct signatures.
    _verifyOrderStateAndSignature(
      tradeData.orderA,
      orderAHash,
      tradeData.fill,
      tradeData.signatureA,
      tradeTimestamp,
      price
    );

    _verifyOrderStateAndSignature(
      tradeData.orderB,
      orderBHash,
      tradeData.fill,
      tradeData.signatureB,
      tradeTimestamp,
      price
    );

    // Classify both signed orders BEFORE any execution price is substituted
    // below. A signed zero price is what makes an order a market order, and the
    // per-order-type quantity cap depends on that classification.
    bool orderAWasMarketOrder = tradeData.orderA.price == 0;
    bool orderBWasMarketOrder = tradeData.orderB.price == 0;

    // Limit price is 0 for market orders. Signatures are verified against
    // price=0 above; after that, substitute the actual fill price so market
    // orders pass the same fill-price checks regardless of which side FBA
    // assigned as maker. This matters for forced liquidation orders, which
    // must remain the taker even when the counterparty is also a market order.
    if (orderAWasMarketOrder) {
      tradeData.orderA.price = tradeData.fill.price;
    }
    if (orderBWasMarketOrder) {
      tradeData.orderB.price = tradeData.fill.price;
    }

    // verify maker/taker, orders can be filled at their desired price.
    //
    // This also reports, per side, whether the fill is an exact and strictly
    // risk-reducing full close of that side's live position. Such a fill is
    // exempt from the quantity grid and the order-type cap (audit issue #78): a
    // configuration change can raise minQty above an existing position or
    // leave it off the new step, and without the exemption no reduce-only close
    // or forced liquidation could take that position (or its off-grid
    // remainder) to zero; a cap lowered below it would block closing it in one
    // signed order. See `_verifyOrderFills` for why the exemption can never
    // open, grow, or flip the exiting side's position.
    (bool orderAExactFullExit, bool orderBExactFullExit) = _verifyTradeRequest(
      tradeData,
      maker,
      taker,
      tradeTimestamp
    );

    // verify that trade conforms to price/quantity/market take bound checks;

    IEvaluator(evaluator).verifyPriceChecks(tradeData.fill.price, maker);

    // The fill grid (min quantity + step size) is a property of the executed
    // fill, which both sides share. It is waived only when the fill exactly
    // closes one side's whole position.
    if (!orderAExactFullExit && !orderBExactFullExit) {
      IEvaluator(evaluator).verifyFillQuantityGrid(
        tradeData.fill.quantity,
        maker
      );
    }

    // The order-type maximums bound each *signed user order's* own total
    // quantity, so order A and order B are checked separately against their own
    // cap: their signed quantities and order types can differ, and each side's
    // exemption is likewise its own.
    //
    // A forced liquidation order is not a signed user order and is never capped
    // -- see the scope note on `Evaluator.verifySignedOrderQuantityCap`. A cap
    // would let a market's own configuration block the liquidation of a
    // position larger than that cap, exactly when the exit matters most.
    // `_verifyForcedLiquidationOrder` bounds a forced fill instead by
    // `fill.quantity <= order.quantity` and `fill.quantity <= balance.qPos`,
    // and the off-chain planner owns its per-batch chunk sizing.
    if (!orderAForcedLiquidation && !orderAExactFullExit) {
      IEvaluator(evaluator).verifySignedOrderQuantityCap(
        tradeData.orderA.quantity,
        orderAWasMarketOrder,
        maker
      );
    }
    if (!orderBForcedLiquidation && !orderBExactFullExit) {
      IEvaluator(evaluator).verifySignedOrderQuantityCap(
        tradeData.orderB.quantity,
        orderBWasMarketOrder,
        taker
      );
    }

    IEvaluator(evaluator).verifyMarketTakeBoundChecks(
      tradeData.fill.price,
      price,
      _isBuy(tradeData.orderB),
      taker
    );

    // Order B always receives the historical taker-side protection above.
    // Order A normally relies on its signed limit, but a signed zero-price
    // market order has no limit and needs the same direction-aware oracle
    // bound regardless of how the batch assigned maker/taker roles.
    if (orderAWasMarketOrder) {
      IEvaluator(evaluator).verifyMarketTakeBoundChecks(
        tradeData.fill.price,
        price,
        _isBuy(tradeData.orderA),
        maker
      );
    }

    // Audit #61: whitelist entries are discounts only. The
    // effective rate is min(customFee, current default), so an entry stored
    // before a later default reduction can never charge above the live
    // default, regardless of setter ordering. The default is one external
    // view read per side; the non-whitelisted path already performed the
    // same read here.
    uint128 makerFeeRate = IPerpetual(perpetual).defaultMakerFee();
    WhitelistedTrader storage makerEntry = whitelistedTraders[maker];
    if (makerEntry.status == true && makerEntry.makerFee < makerFeeRate) {
      makerFeeRate = makerEntry.makerFee;
    }

    uint128 takerFeeRate = IPerpetual(perpetual).defaultTakerFee();
    WhitelistedTrader storage takerEntry = whitelistedTraders[taker];
    if (takerEntry.status == true && takerEntry.takerFee < takerFeeRate) {
      takerFeeRate = takerEntry.takerFee;
    }
    bool isBinaryMarket = IPerpetual(perpetual).isBinaryFutureMarket();

    IMResponse memory makerData = _applyIM(
      tradeData.orderA,
      tradeData.fill,
      _feePerUnit(tradeData.fill.price, makerFeeRate, isBinaryMarket),
      price
    );

    IMResponse memory takerData = _applyIM(
      tradeData.orderB,
      tradeData.fill,
      _feePerUnit(tradeData.fill.price, takerFeeRate, isBinaryMarket),
      price
    );

    return
      Types.TradeResult({
        makerHash: orderAHash,
        takerHash: orderBHash,
        makerBalance: makerData.balance,
        takerBalance: takerData.balance,
        makerFundsFlow: makerData.fundsFlow,
        takerFundsFlow: takerData.fundsFlow,
        makerFee: makerData.fee,
        takerFee: takerData.fee,
        makerPnl: makerData.pnl,
        takerPnl: takerData.pnl,
        tradeQuantity: tradeData.fill.quantity,
        price: tradeData.fill.price,
        isBuy: _isBuy(tradeData.orderB), // from taker's perspective
        traderFlags: orderAForcedLiquidation
          ? DUAL_LIQUIDATION_TRADER_ID
          : orderBForcedLiquidation
            ? LIQUIDATION_TRADER_ID
            : TRADER_ID
      });
  }

  //===========================================================//
  //                         SETTERS
  //===========================================================//

  /**
   * @notice sets current cancellation operator to new operator provided.
   * @param _newOperator address of new operator
   */
  function setCancellationOperator(
    address _newOperator
  ) public onlyOwner nonReentrant {
    require(
      _newOperator != cancellationOperator,
      'IsolatedTrader: New cancellation operator should be different from current one'
    );
    cancellationOperator = _newOperator;
    emit CancellationOperatorUpdate(cancellationOperator);
  }

  /**
   * @notice On-chain cancels an order.
   * @param _order The order that will be permanently canceled.
   */
  function cancelOrder(Order calldata _order) public {
    /**
     * @dev using msgSender() instead of _msgSender(), as maker cancellation is
     * an advertised relayed user action. For a call routed through the trusted
     * forwarder, _msgSender() is the forwarder rather than the maker appended
     * to the calldata, so the check would reject a correctly authorized
     * request. cancelOrders() inherits this via its internal calls.
     */
    address maker = msgSender();
    require(
      maker == _order.maker,
      'IsolatedTrader: Order cannot be canceled by non-maker'
    );
    bytes32 orderHash = _getOrderHash(_order);
    _setCanceled(orderHash);
    emit OrderCancel(maker, orderHash, _blockTimestamp());
  }

  /**
   * @notice Sets a trader's whitelist status and custom maker and taker fee rates.
   * @dev Custom fees replace Perpetual's default maker/taker fees during trade
   * execution, so they carry the same 25% ceiling those defaults enforce
   * (`BaseMath.MAX_TRADE_FEE`, checked by Perpetual as P25/P26). Audit #61
   * additionally makes whitelist entries discounts only: each
   * custom fee must not exceed its corresponding current default (P33), and
   * the trade path clamps the effective rate to min(customFee, live default),
   * so a later default reduction can never leave an entry charging above it.
   * All bounds apply to the stored values regardless of `status`, so an
   * inactive entry can never be flipped active while holding an out-of-bounds
   * fee.
   */
  function setWhitelistedTrader(
    address account,
    bool status,
    uint128 makerFee,
    uint128 takerFee
  ) public onlyOwner nonReentrant {
    require(
      makerFee <= BaseMath.MAX_TRADE_FEE,
      'IsolatedTrader: Maker fee exceeds maximum trade fee'
    );
    require(
      takerFee <= BaseMath.MAX_TRADE_FEE,
      'IsolatedTrader: Taker fee exceeds maximum trade fee'
    );
    require(makerFee <= IPerpetual(perpetual).defaultMakerFee(), 'P33');
    require(takerFee <= IPerpetual(perpetual).defaultTakerFee(), 'P33');

    whitelistedTraders[account] = WhitelistedTrader({
      status: status,
      makerFee: makerFee,
      takerFee: takerFee
    });

    emit TraderWhitelisted(account, status, makerFee, takerFee);
  }

  /**
   * @notice On-chain cancels list of given order.
   * @param _orders The orders that will be permanently canceled.
   */
  function cancelOrders(Order[] calldata _orders) public {
    for (uint128 i = 0; i < _orders.length; i++) {
      cancelOrder(_orders[i]);
    }
  }

  /**
   * @notice Cancel an order on-chain
   * @param  _orderHash  Hash of the order to be canceled
   */
  function cancelOrderByHash(
    bytes32 _orderHash
  ) public onlyCancellationOperator {
    _setCanceled(_orderHash);
    emit OrderCancelledByOperator(_orderHash, _blockTimestamp());
  }

  /**
   * @notice On-chain cancels list of given order.
   * @param  _orderHashes  Hashes of orders that will be permanently canceled.
   */
  function cancelOrdersByHash(
    bytes32[] calldata _orderHashes
  ) public onlyCancellationOperator {
    for (uint128 i = 0; i < _orderHashes.length; i++) {
      cancelOrderByHash(_orderHashes[i]);
    }
  }

  //===========================================================//
  //                         GETTERS
  //===========================================================//

  /**
   * @notice returns the trader flag
   */
  function getTraderFlag() public pure override returns (bytes32) {
    return TRADER_ID;
  }

  /**
   * @notice Gets the status (open/canceled) and filled amount of each order in a list.
   * @param  _orderHashes list of order hashes to get
   * @return A list of OrderStatusQuery structs containing the status and filled
   * amount of each order.
   */
  function getOrdersStatus(
    bytes32[] calldata _orderHashes
  ) external view returns (OrderStatusQuery[] memory) {
    OrderStatusQuery[] memory result = new OrderStatusQuery[](
      _orderHashes.length
    );
    for (uint128 i = 0; i < _orderHashes.length; i++) {
      bytes32 orderHash = _orderHashes[i];
      result[i] = OrderStatusQuery({
        status: _isCanceled(orderHash)
          ? OrderStatus.Canceled
          : OrderStatus.Open,
        filledAmount: _getFilledQuantity(orderHash)
      });
    }
    return result;
  }

  /**
   * @notice Computes EIP712 hash and returns it
   * @param _order Order
   * @return Returns the EIP712 hash of an order.
   */
  function getOrderHash(Order memory _order) public view returns (bytes32) {
    return _getOrderHash(_order);
  }

  //===========================================================//
  //                      INTERNAL METHODS
  //===========================================================//

  /**
   * @dev applies isolated margin to the account placing the order
   * @param order Order on which IM is to be applied
   * @param fill Fill quantity of trade
   * @param feePerUnit Fee per unit (Maker or taker) for the trade
   */
  function _applyIM(
    Order memory order,
    Fill memory fill,
    uint128 feePerUnit,
    uint128 oraclePrice
  ) internal view returns (IMResponse memory) {
    IMVariables memory vars;

    Types.PositionBalance memory balance = IPerpetual(perpetual)
      .getAccountBalance(order.maker);
    Types.PositionBalance memory beforeBalance = Types.PositionBalance({
      isPosPositive: balance.isPosPositive,
      mro: balance.mro,
      qPos: balance.qPos,
      margin: balance.margin,
      oiOpen: balance.oiOpen
    });
    balance.mro = BaseMath.baseUInt().baseDiv(order.leverage);

    vars.isBuy = _isBuy(order);
    vars.isReduceOnly = _isReduceOnly(order);
    vars.isBinaryMarket = IPerpetual(perpetual).isBinaryFutureMarket();

    vars.pPos = balance.oiOpen == 0 ? 0 : balance.oiOpen.baseDiv(balance.qPos);

    // case 1: Opening position or adding to position size
    if (balance.qPos == 0 || vars.isBuy == balance.isPosPositive) {
      balance.oiOpen = balance.oiOpen + fill.quantity.baseMul(fill.price);
      balance.qPos = balance.qPos + fill.quantity;
      uint128 openingMargin = _getOpeningMarginAmount(
        fill.quantity,
        fill.price,
        balance.mro,
        vars.isBuy,
        vars.isBinaryMarket
      );
      vars.fundsFlow = int256(
        uint256(openingMargin + fill.quantity.baseMul(feePerUnit))
      );
      balance.margin = balance.margin + openingMargin;
      balance.isPosPositive = vars.isBuy;

      IEvaluator(evaluator).verifyOpenNotionalTransitionForAccount(
        order.maker,
        beforeBalance,
        balance,
        oraclePrice
      );
    }
    // case 2: Reduce only order
    else if (
      vars.isReduceOnly ||
      (vars.isBuy != balance.isPosPositive && fill.quantity <= balance.qPos)
    ) {
      vars.oldQPos = balance.qPos;

      balance.qPos = balance.qPos - fill.quantity;

      // Floor the closed legs once, then derive retained accounting by
      // subtraction. Scaling each retained leg independently can round both
      // down and make a fully collateralized binary short one wei short of its
      // max-loss floor. The retained dust keeps margin, and a long's cost
      // basis, on the conservative side; a short's retained oiOpen can sit up
      // to one wei high, which favors the short. The final close releases it
      // because fill.quantity == oldQPos.
      uint128 closedOiOpen = BaseMath.mulDiv(
        balance.oiOpen,
        fill.quantity,
        vars.oldQPos
      );
      balance.oiOpen = balance.oiOpen - closedOiOpen;
      uint128 closedMargin = BaseMath.mulDiv(
        balance.margin,
        fill.quantity,
        vars.oldQPos
      );
      uint128 remainingMargin = balance.margin - closedMargin;

      vars.marginPerUnit = balance.margin.baseDiv(vars.oldQPos);

      vars.pnlPerUnit = balance.isPosPositive
        ? int256(uint256(fill.price)) - int256(uint256(vars.pPos))
        : int256(uint256(vars.pPos)) - int256(uint256(fill.price));

      vars.equityPerUnit =
        int256(uint256(vars.marginPerUnit)) +
        vars.pnlPerUnit;

      Require.that(
        vars.equityPerUnit >= 0,
        'Cannot trade when loss exceeds margin. Please add margin',
        order.maker
      );

      if (feePerUnit > vars.equityPerUnit.toPositive()) {
        feePerUnit = vars.equityPerUnit.toPositive();
      }

      vars.fundsFlow =
        fill.quantity.baseMul(-vars.pnlPerUnit + int256(uint256(feePerUnit))) -
        int256(uint256(closedMargin));

      vars.fundsFlow = vars.fundsFlow > int256(0) ? int256(0) : vars.fundsFlow;

      balance.margin = remainingMargin;

      // even if position size is zero we are setting isPosPositive to false
      // this is what default value for isPosPositive is
      balance.isPosPositive = balance.qPos > 0 ? balance.isPosPositive : false;

      vars.pnlPerUnit = vars.pnlPerUnit.baseMul(int256(int128(fill.quantity)));
    }
    // case 3: flipping position side
    else {
      uint128 oldQPos = balance.qPos;
      balance.qPos = fill.quantity - balance.qPos;

      balance.oiOpen = balance.qPos.baseMul(fill.price);

      vars.marginPerUnit = balance.margin.baseDiv(oldQPos);

      vars.pnlPerUnit = balance.isPosPositive
        ? int256(uint256(fill.price)) - int256(uint256(vars.pPos))
        : int256(uint256(vars.pPos)) - int256(uint256(fill.price));

      vars.equityPerUnit =
        int256(uint256(vars.marginPerUnit)) +
        vars.pnlPerUnit;

      Require.that(
        vars.equityPerUnit >= 0,
        'Cannot trade when loss exceeds margin. Please add margin',
        order.maker
      );

      // fee paid on closing the current position
      uint128 closingFeePerUnit = feePerUnit;

      if (closingFeePerUnit > vars.equityPerUnit.toPositive()) {
        closingFeePerUnit = vars.equityPerUnit.toPositive();
      }

      vars.fundsFlow =
        oldQPos.baseMul(
          -1 * vars.pnlPerUnit + int256(uint256(closingFeePerUnit))
        ) -
        int256(uint256(balance.margin)) +
        int256(
          uint256(
            _getOpeningMarginAmount(
              balance.qPos,
              fill.price,
              balance.mro,
              vars.isBuy,
              vars.isBinaryMarket
            ) + balance.qPos.baseMul(feePerUnit)
          )
        );

      balance.isPosPositive = !balance.isPosPositive;

      feePerUnit = ((oldQPos.baseMul(closingFeePerUnit)) +
        (balance.qPos.baseMul(feePerUnit))).baseDiv(fill.quantity);
      IEvaluator(evaluator).verifyOpenNotionalTransitionForAccount(
        order.maker,
        beforeBalance,
        balance,
        oraclePrice
      );

      balance.margin = _getOpeningMarginAmount(
        balance.qPos,
        fill.price,
        balance.mro,
        vars.isBuy,
        vars.isBinaryMarket
      );
      vars.pnlPerUnit = vars.pnlPerUnit.baseMul(int256(uint256(oldQPos)));
    }

    //  if position is closed due to reducing trade or liquidaiton,
    // reset mro to zero
    if (balance.qPos == 0) {
      balance.mro = 0;
    }

    return
      IMResponse({
        balance: balance,
        fundsFlow: vars.fundsFlow,
        pnl: vars.pnlPerUnit,
        fee: feePerUnit.baseMul(fill.quantity)
      });
  }

  function _getOpeningMarginAmount(
    uint128 quantity,
    uint128 price,
    uint128 mro,
    bool isBuy,
    bool isBinaryMarket
  ) internal pure returns (uint128) {
    if (isBinaryMarket && !isBuy) {
      uint128 entryNotional = quantity.baseMul(price);
      uint128 exposure = quantity > entryNotional
        ? quantity - entryNotional
        : 0;
      return exposure.baseMulRoundUp(mro);
    }

    return quantity.baseMul(price).baseMulRoundUp(mro);
  }

  /**
   * Binary fees use payout variance, `rate * p * (1-p)`, so the fee remains a
   * bounded fraction of either side's remaining loss capacity. Other market
   * types retain the historical price-notional fee base.
   */
  function _feePerUnit(
    uint128 price,
    uint128 feeRate,
    bool isBinaryMarket
  ) internal pure returns (uint128) {
    uint128 feeBase = isBinaryMarket
      ? price.baseMul(BaseMath.baseUInt() - price)
      : price;
    return feeBase.baseMul(feeRate);
  }

  /**
   * @dev Verifies one side of a fill. A forced liquidation order is checked by
   * `_verifyForcedLiquidationOrder` instead, with no signature or cancel check.
   * Any other order must meet its trigger condition, not be canceled, and be
   * signed by an address with this market's permission for `order.maker`
   * (reduce-only permission accepts only reduce-only orders); its fill is then
   * recorded against the signed quantity.
   * @param order Order to be verified
   * @param orderHash hash of the above provided order
   * @param signature signature of the order
   */
  function _verifyOrderStateAndSignature(
    Order memory order,
    bytes32 orderHash,
    Fill memory fill,
    TypedSignature.Signature memory signature,
    uint128 tradeTimestamp,
    uint128 oraclePrice
  ) internal {
    if (_isForcedLiquidation(order)) {
      _verifyForcedLiquidationOrder(order, fill, tradeTimestamp, oraclePrice);
      return;
    }

    // Audit #50: validate and enforce the signed trigger condition before
    // any fill of this order is recorded.
    _verifyTriggerCondition(order, oraclePrice);

    Require.that(
      !_isCanceled(orderHash),
      'IsolatedTrader: Order was already canceled',
      order.maker
    );

    // recover address from signature
    address sigMaker = TypedSignature.recover(orderHash, signature);

    // If not cancelled, order is open. Proceed to verify signature
    // if recovered address is 0, it implies incorrect order signature
    //
    // Market-scoped since audit #38. For a vault child this asks whether the
    // signer may trade THIS market, not whether it holds a blanket approval;
    // for an ordinary user the answer is the same global one as before. Placed
    // after the forced-liquidation branch above returns, so a liquidation still
    // needs no maker permission and a wind-down cannot become unliquidatable.
    Types.MarketPermission permission = sigMaker == address(0)
      ? Types.MarketPermission.NONE
      : IPerpetual(perpetual).accountMarketPermission(order.maker, sigMaker);
    Require.that(
      permission != Types.MarketPermission.NONE,
      'IsolatedTrader: Order has an invalid signature',
      order.maker
    );
    // Reduce-only may still close: only orders that shrink exposure pass.
    Require.that(
      permission == Types.MarketPermission.ACTIVE || _isReduceOnly(order),
      'IsolatedTrader: Market is reduce-only for this account',
      order.maker
    );

    // fill quantity of order
    _fillQuantity(order, orderHash, fill, sigMaker, tradeTimestamp);
  }

  function _verifyForcedLiquidationOrder(
    Order memory order,
    Fill memory fill,
    uint128 tradeTimestamp,
    uint128 oraclePrice
  ) internal view {
    Require.that(
      _isReduceOnly(order),
      'IsolatedTrader: Forced liquidation must be reduce-only',
      order.maker
    );

    Require.that(
      order.price == 0,
      'IsolatedTrader: Forced liquidation must be market order',
      order.maker
    );

    // Audit #50: forced liquidation orders are protocol-generated and
    // unsigned; they must never carry a trigger condition. 'P84' here means
    // the settlement operator built a malformed forced order — a protocol
    // fault, never a user's.
    Require.that(
      order.triggerCondition == uint8(Types.TriggerCondition.NONE),
      'P84',
      order.maker
    );
    // With the condition pinned to NONE, the shared shape check reduces to
    // "triggerPrice must be zero" ('P82').
    _verifyTriggerCondition(order, oraclePrice);

    _verifyOrderMaker(order, order.maker, tradeTimestamp);

    Types.PositionBalance memory balance = IPerpetual(perpetual)
      .getAccountBalance(order.maker);

    Require.that(
      balance.qPos > 0,
      'IsolatedTrader: Forced liquidation account has no position',
      order.maker
    );

    Require.that(
      _isBuy(order) != balance.isPosPositive,
      'IsolatedTrader: Forced liquidation must reduce position',
      order.maker
    );

    Require.that(
      fill.quantity <= balance.qPos,
      'IsolatedTrader: Forced liquidation cannot flip position',
      order.maker
    );

    // A forced liquidation order returns from _verifyOrderStateAndSignature
    // before _fillQuantity, so it never reaches the overfill guard that bounds
    // an ordinary order's cumulative fills by its own signed quantity. Bound a
    // single forced fill by the order it belongs to here. Defence in depth: the
    // planner already sizes forced orders, and the qPos bound above stops a
    // flip, but nothing else stops an operator or planner bug from filling more
    // than the forced order asked for.
    Require.that(
      fill.quantity <= order.quantity,
      'IsolatedTrader: Forced liquidation fill exceeds order quantity',
      order.maker
    );

    int256 marginRatio = PositionBalanceMath.getMarginRatioWithBinaryCheck(
      balance,
      oraclePrice,
      IPerpetual(perpetual).isBinaryFutureMarket()
    );

    Require.that(
      marginRatio < IPerpetual(perpetual).maintenanceMarginRequired(),
      'IsolatedTrader: Account is not liquidatable',
      order.maker
    );
  }

  /**
   * @dev Audit #50: validates the signed trigger fields and enforces the
   * signed condition against the oracle price before any fill, relaxed
   * one-sidedly by this market's trigger band (amended 2026-08-03).
   *
   * The `oraclePrice` argument is `Perpetual.trade()`'s cached-context
   * oracle price (`Types.Context.price`) — the same value already used for
   * market-take bounds and forced-liquidation eligibility. `trade()` does not
   * read `block.timestamp` (MegaETH's volatile-context compute ceiling), so
   * freshness of this check is bounded by the global-index batch budget and
   * the dedicated updater lane (the audit #51 trust boundary), not by wall
   * clock.
   *
   * The band exists because the two sides evaluate different prices on
   * purpose: off-chain activation uses MARK price, the price the product shows
   * and users set triggers against, while only the ORACLE price is
   * authenticated on-chain. For non-binary markets, `bandAmount` is an e18
   * fraction (`triggerBand`, or the order's own-side take bound when it is zero)
   * times `oraclePrice`. For binary markets, a positive explicit band is
   * an absolute payout-price delta, while the zero sentinel resolves to the
   * price-dependent directional execution amount derived from remaining side
   * capacity.
   *
   * The relaxation is ONE-SIDED — the band is added only on the not-yet-met
   * side, never on the already-satisfied one:
   *
   *   PRICE_AT_OR_ABOVE  satisfied iff  oraclePrice >= triggerPrice - band
   *   PRICE_AT_OR_BELOW  satisfied iff  oraclePrice <= triggerPrice + band
   *
   * Overshoot therefore always satisfies: an oracle far ABOVE an at-or-above
   * trigger passes, and no band width can turn it into a rejection. That is
   * the whole reason a symmetric "within one band of the trigger" variant was
   * rejected — a fast gap straight through the trigger price is precisely when
   * a stop must fill, and a symmetric window would block it.
   *
   * #49's oracle-relative take bound still caps the fill price in the order's
   * adverse direction when it is order B or a zero-price order A; a limit
   * order A relies on its own signed limit price instead.
   *
   * Revert codes:
   *   'P81' — unknown/reserved triggerCondition value. Values above
   *           PRICE_AT_OR_BELOW are rejected, never treated as NONE; that
   *           is what lets future authenticated mark-price conditions claim
   *           them without a second signature cutover.
   *   'P82' — condition/price shape mismatch: NONE with a nonzero
   *           triggerPrice, or a conditional value with a zero triggerPrice.
   *   'P83' — the signed condition is not met at the cached-context oracle
   *           price, after the band shift.
   */
  function _verifyTriggerCondition(
    Order memory order,
    uint128 oraclePrice
  ) internal view {
    Require.that(
      order.triggerCondition <= uint8(Types.TriggerCondition.PRICE_AT_OR_BELOW),
      'P81',
      order.maker
    );

    if (order.triggerCondition == uint8(Types.TriggerCondition.NONE)) {
      Require.that(order.triggerPrice == 0, 'P82', order.maker);
      return;
    }

    Require.that(order.triggerPrice > 0, 'P82', order.maker);

    // Read the band only on the conditional path: an unconditional order and a
    // forced liquidation both return above, so neither pays for this call.
    // `_isBuy(order)` selects the side exactly as the market-take-bound check
    // does, so the sentinel default is this order's own execution bound.
    uint128 bandAmount = IEvaluator(evaluator).triggerBandAmountFor(
      _isBuy(order),
      oraclePrice
    );

    if (
      order.triggerCondition == uint8(Types.TriggerCondition.PRICE_AT_OR_ABOVE)
    ) {
      // oraclePrice >= triggerPrice - bandAmount, written so the subtraction
      // cannot underflow: a band wider than the trigger price saturates the
      // shifted threshold at zero, which every oracle price satisfies.
      Require.that(
        order.triggerPrice <= bandAmount ||
          oraclePrice >= order.triggerPrice - bandAmount,
        'P83',
        order.maker
      );
    } else {
      // oraclePrice <= triggerPrice + bandAmount, written as a subtraction on
      // the oracle side so the sum cannot overflow uint128. Any oracle at or
      // below the trigger is overshoot and passes without consulting the band.
      Require.that(
        oraclePrice <= order.triggerPrice ||
          oraclePrice - order.triggerPrice <= bandAmount,
        'P83',
        order.maker
      );
    }
  }

  /**
   * @dev verifies if the trade request is correct or not
   * @param tradeData containing TradeData
   * @param maker address of the maker account
   * @param taker address of the taker account
   * @return orderAExactFullExit whether order A's fill exactly closes order A's
   * whole live position, and is therefore exempt from the quantity grid and the
   * order-type cap (audit issue #78)
   * @return orderBExactFullExit the same, for order B
   */
  function _verifyTradeRequest(
    TradeData memory tradeData,
    address maker,
    address taker,
    uint128 tradeTimestamp
  ) internal view returns (bool orderAExactFullExit, bool orderBExactFullExit) {
    Require.that(
      _isBuy(tradeData.orderA) != _isBuy(tradeData.orderB),
      "IsolatedTrader: Maker and Taker orders can't be of same side",
      taker
    );

    // orderA.maker should be the maker of the trade
    _verifyOrderMaker(tradeData.orderA, maker, tradeTimestamp);

    // orderB.maker should be the taker of the trade
    _verifyOrderMaker(tradeData.orderB, taker, tradeTimestamp);

    // confirm that both orders can be filled
    orderAExactFullExit = _verifyOrderFills(tradeData.orderA, tradeData.fill);
    orderBExactFullExit = _verifyOrderFills(tradeData.orderB, tradeData.fill);

    // confirm that the leverage of the order is same as MRO;
    _verifyOrderLeverage(maker, tradeData.orderA.leverage);
    _verifyOrderLeverage(taker, tradeData.orderB.leverage);
  }

  /**
   * @dev verifies if the order leverage is correct or not
   * @param account address of the account
   * @param leverage current leverage specified in order
   */
  function _verifyOrderLeverage(
    address account,
    uint128 leverage
  ) internal view {
    Require.that(leverage > 0, 'Leverage must be > 0', account);
    Require.that(
      leverage % BaseMath.baseUInt() == 0,
      'Invalid leverage',
      account
    );
    Types.PositionBalance memory balance = IPerpetual(perpetual)
      .getAccountBalance(account);
    // Allow any leverage if no position exists (qPos == 0) or mro hasn't been set,
    // otherwise require leverage to match existing mro
    Require.that(
      balance.qPos == 0 ||
        balance.mro == 0 ||
        BaseMath.baseUInt().baseDiv(leverage) == balance.mro,
      'Invalid leverage',
      account
    );
  }

  /**
   * @dev confirms if the maker and taker of the provided order are correct.
   * @param order   orders data to be verified
   * @param maker   maker's address
   */
  function _verifyOrderMaker(
    Order memory order,
    address maker,
    uint128 tradeTimestamp
  ) internal pure {
    // order.maker should be the maker of the trade
    require(
      order.maker == maker,
      'IsolatedTrader: Order maker does not match trade maker'
    );

    // confirm that the order is not expired
    // order with expiration = 0 will never expire by itself; a user must cancel it.
    Require.that(
      order.expiration >= tradeTimestamp || order.expiration == 0,
      'IsolatedTrader: Order has expired',
      order.maker
    );
  }

  /**
   * @dev Verifies that the fill satisfies the order's limit price (orders carry
   * no fee bound), and reports whether the fill is an exact, strictly
   * risk-reducing full close of the order maker's live position.
   *
   * A full-exit fill is exempt from the quantity grid and the order-type cap
   * (audit issue #78). All three conditions below must hold, and together they
   * make it impossible for the exemption to open, grow, or flip this order's
   * own position:
   *   1. the order is reduce-only (forced liquidation orders always are, and
   *      are separately required to be so in `_verifyForcedLiquidationOrder`),
   *   2. the order is on the strictly opposite side of a live position, and
   *   3. the fill closes that position exactly -- not a wei more or less.
   *
   * A partial off-grid reduction fails condition 3. A new position or a
   * same-side add fails condition 2. A flip needs `fill.quantity > qPos`, which
   * also fails condition 3. Price checks and the market-take-bound checks are
   * unaffected: this only waives quantity-grid and cap validation.
   *
   * Conditions 1 and 2 and the `fill.quantity <= qPos` half of condition 3 are
   * exactly the reduce-only requirement already enforced below, so this is
   * decided from the balance this function already loads rather than from a
   * second `getAccountBalance` staticcall per order.
   *
   * @param  order      The order to verify.
   * @param  fill       The fill data to verify against the order.
   * @return isExactFullExit whether the fill exactly closes the maker's whole
   * live position.
   */
  function _verifyOrderFills(
    Order memory order,
    Fill memory fill
  ) private view returns (bool isExactFullExit) {
    bool isBuyOrder = _isBuy(order); // from the maker's perspective.

    // Ensure order is being filled at the specified or better price
    // For long/buy orders, the fill price must be equal or lower
    // For short/sell orders, the fill price must be equal or higher
    bool validPrice = isBuyOrder
      ? fill.price <= order.price
      : fill.price >= order.price;

    Require.that(
      validPrice,
      'IsolatedTrader: Fill price is invalid',
      order.maker
    );

    // For reduce only orders, ensure that the order would result in an
    // open position's size to reduce (fill amount <= open position size)

    if (_isReduceOnly(order)) {
      Types.PositionBalance memory balance = IPerpetual(perpetual)
        .getAccountBalance(order.maker);
      Require.that(
        isBuyOrder != balance.isPosPositive && // Reduce only order must be in the opposite direction as open position (a positive position size means open position is Buy)
          fill.quantity <= balance.qPos, // Reduce-only fill quantity must not exceed the open
          // position size. The side is stored separately (isPosPositive), so this compares
          // absolute sizes regardless of position direction (Buy or Sell)
        'IsolatedTrader: Fill does not decrease size',
        order.maker
      );

      // The Require above already established reduce-only, opposite side, and
      // `fill.quantity <= qPos`, so an exact match against a live position is
      // the full-exit case. `qPos > 0` keeps a zero-quantity fill against an
      // empty position from reading as one.
      isExactFullExit = balance.qPos > 0 && fill.quantity == balance.qPos;
    }
  }

  /**
   * @dev Updates the order's filled amount in the packed `orderState` map
   * @param  order  The order to update filled amount against
   * @param  orderHash The hash of the order
   * @param  fill   Fill struct specifying fill amount
   */
  function _fillQuantity(
    Order memory order,
    bytes32 orderHash,
    Fill memory fill,
    address sigMaker,
    uint128 tradeTimestamp
  ) private {
    uint128 newFilledQuantity = _getFilledQuantity(orderHash) + fill.quantity;

    Require.that(
      newFilledQuantity <= order.quantity,
      'IsolatedTrader: Cannot overfill maker order',
      order.maker
    );

    _setFilledQuantity(orderHash, newFilledQuantity);

    emit OrderFill(
      orderHash,
      order,
      sigMaker,
      fill,
      newFilledQuantity,
      tradeTimestamp
    );
  }

  /**
   * @dev Returns the EIP712 hash of an order.
   */
  function _getOrderHash(Order memory order) internal view returns (bytes32) {
    // compute the overall signed struct hash
    bytes32 structHash = keccak256(
      abi.encode(EIP712_ORDER_STRUCT_SCHEMA_HASH, order)
    );

    // compute eip712 compliant hash
    return computeEIP712MessageHash(_EIP712_DOMAIN_HASH_, structHash);
  }

  /**
   * @dev returns true if order is of long side
   */
  function _isBuy(Order memory order) private pure returns (bool) {
    return isBuyFlag(order.flags);
  }

  /**
   * @dev returns true if order is reduce only
   */
  function _isReduceOnly(Order memory order) private pure returns (bool) {
    return isReduceOnlyFlag(order.flags);
  }

  function _isForcedLiquidation(
    Order memory order
  ) private pure returns (bool) {
    return isForcedLiquidationFlag(order.flags);
  }
}
