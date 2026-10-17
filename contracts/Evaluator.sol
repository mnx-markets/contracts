// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

//utils
import {Ownable2StepUpgradeable} from '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol';

// interfaces
import {IEvaluator} from './interfaces/IEvaluator.sol';

// maths
import {BaseMath} from './maths/BaseMath.sol';
// Imported for its BINARY_MIN_PRICE / BINARY_MAX_PRICE constants and for
// isRiskIncreasingTransition, which classifies the before -> after transitions
// that verifyOpenNotionalTransitionForAccount checks.
import {PositionBalanceMath} from './maths/PositionBalanceMath.sol';

// libraries
import {Types} from './libraries/Types.sol';
import {Require} from './libraries/Require.sol';

/**
 * @title Evaluator
 * @author MNX Markets <help@mnx.fi>
 * @notice Stores perpetual configurations and evaluates if a trade is allowed to be executed based on perpetual configurations.
 * Houses the variables needed to perform pre-trade checks for price, quantity and max allowed open notional.
 * Implements IEvalautor interface to allow contracts to acccess these variables
 * @dev The contract is made upgradable using openzeppelin upgrades-pluging, don't change
 * the order of variables. Read more: https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies
 */
contract Evaluator is IEvaluator, Ownable2StepUpgradeable {
  using BaseMath for uint128;

  //
  // EVENTS
  //

  /// @notice Emitted when min price is set
  event MinOrderPriceUpdate(uint128 newPrice);

  /// @notice Emitted when max price is set
  event MaxOrderPriceUpdate(uint128 newPrice);

  /// @notice Emitted when tick size is set
  event TickSizeUpdate(uint128 newSize);

  /// @notice Emitted when min quantityis set
  event MinQuantityUpdate(uint128 newQuantity);

  /// @notice Emitted when max limit quantity is set
  event MaxQuantityLimitUpdate(uint128 newQuantity);

  /// @notice Emitted when max market quantity is set
  event MaxQuantityMarketUpdate(uint128 newQuantity);

  /// @notice Emitted when market take bound long is set
  event MTBLongUpdate(uint128 newValue);

  /// @notice Emitted market take bound short is set
  event MTBShortUpdate(uint128 newValue);

  /// @notice Emitted when step size is set
  event StepSizeUpdate(uint128 newSize);

  /// @notice Emitted when max open notional for leverage is set
  event MaxOpenNotionalUpdate(uint128 leverage, uint128 maxAllowedOpenNotional);

  /// @notice Emitted when binary-market price bounds are locked.
  event BinaryMarketPriceBoundsLocked();

  event BinaryTakeRiskFractionUpdate(uint128 riskFraction);

  /// @notice Emitted when the audit-#50 trigger band is set. `newValue` is the
  /// stored value, so zero reports a return to the market-take-bound default.
  event TriggerBandUpdate(uint128 newValue);

  //**********************************************************//
  //    The below state variables can not change the order    //
  //**********************************************************//

  /// @notice minimum price at which asset can be traded
  uint128 public override minPrice;

  /// @notice maximum price at which asset can be traded
  uint128 public override maxPrice;

  /// @notice the smallest decimal unit supported by asset for price
  uint128 public override tickSize;

  /// @notice minimum quantity of asset that can be traded
  uint128 public override minQty;

  /// @notice maximum quantity of asset that can be traded for limit order
  uint128 public override maxQtyLimit;

  /// @notice maximum quantity of asset that can be traded for market order
  uint128 public override maxQtyMarket;

  /// @notice the smallest decimal unit supported by asset for quantity
  uint128 public override stepSize;

  /// @notice Market take-bound fraction for non-binary buys. Retained as a
  /// legacy slot on binary markets, whose effective bound is configured by
  /// `binaryTakeRiskFraction`.
  /// After initialization it can only decrease.
  uint128 public override mtbLong;

  /// @notice Market take-bound fraction for non-binary sells. Retained as a
  /// legacy slot on binary markets, whose effective bound is configured by
  /// `binaryTakeRiskFraction`.
  /// After initialization it can only decrease.
  uint128 public override mtbShort;

  /// @notice Maximum allowed open notional per leverage.
  /// @dev leverage is represented in 18 decimal units
  mapping(uint128 => uint128) public override maxAllowedOpenNotional;

  uint256[50] private __gap;

  uint128 internal constant HALF_BASE_UINT = 5 * 10 ** 17;

  //**********************************************************//
  //    The above state variables can not change the order    //
  //**********************************************************//

  //◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤ add state variables below ◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤//

  /// @notice Number of leverage tiers currently configured in maxAllowedOpenNotional.
  /// @dev Tiers are always set contiguously starting at 1x, so this count is
  /// enough to know which higher tiers to clear when the configured list
  /// shrinks. Set in initialize() and kept current by setMaxOpenNotional().
  uint128 public maxOpenNotionalTierCount;

  /// @notice One-way lock for binary markets whose price band must stay [1 wei, 1e18].
  bool public binaryMarketPriceBoundsLocked;

  /// @notice Audit #50 (amended 2026-08-03): tolerance applied to the on-chain
  /// enforcement of a signed trigger condition. It is an e18 fraction of the
  /// oracle price for non-binary markets and an absolute e18 payout-price delta
  /// for binary markets.
  /// @dev Zero is the sentinel for "use this market's market take bound." For a
  /// binary market that default is not this slot's unit: it is the
  /// price-dependent amount derived from `binaryTakeRiskFraction` and the
  /// remaining side capacity. Enforcement must use `triggerBandAmountFor`.
  uint128 public triggerBand;

  /// @notice Binary execution-bound fraction. Zero means unconfigured and
  /// resolves to a zero-width interval until the paused cutover sets it.
  uint128 public override binaryTakeRiskFraction;

  //◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣ add state variables above ◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣//

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  /**
   * @notice initializes the contract
   * @param _minOrderPrice min price at which order can be executed
   * @param _maxOrderPrice max price at which order can be executed
   * @param _tickSize tick size for price
   * @param _minTradeQty minimum order quantity
   * @param _maxTradeQtyLimit maximum limit order quantity
   * @param _maxTradeQtyMarket maximum market order quantity
   * @param _stepSize step size for quantity
   * @param _mtbLong market take bound for long side
   * @param _mtbShort market take bound for short side
   */
  function initialize(
    uint128 _minOrderPrice,
    uint128 _maxOrderPrice,
    uint128 _tickSize,
    uint128 _minTradeQty,
    uint128 _maxTradeQtyLimit,
    uint128 _maxTradeQtyMarket,
    uint128 _stepSize,
    uint128 _mtbLong,
    uint128 _mtbShort,
    uint128[] calldata _maxOpenNotional
  ) public initializer {
    require(_minOrderPrice > 0, 'Minimum order price must be > 0');
    require(
      _minOrderPrice < _maxOrderPrice,
      'Minimum order price must be <  maximum order price'
    );
    require(
      _minTradeQty < _maxTradeQtyLimit && _minTradeQty < _maxTradeQtyMarket,
      'Minimum trade quantity must be < max trade quantity'
    );
    require(_minTradeQty > 0, 'Minimum trade quantity must be > 0');
    require(_tickSize > 0, 'Tick size must be > 0');
    require(_stepSize > 0, 'Step size must be > 0');
    require(
      _mtbLong > 0 && _mtbShort > 0,
      'Take bounds must be > 0 for both sides'
    );
    // Keep both take-bound fractions below one e18 unit, matching the setters.
    // Non-binary markets enforce them; binary execution ignores them after the
    // one-way regime lock and instead uses `binaryTakeRiskFraction`.
    require(
      _mtbLong < BaseMath.baseUInt(),
      'Market Take Bound for long trades must be < 100%'
    );
    require(
      _mtbShort < BaseMath.baseUInt(),
      'Market Take Bound for short trades must be < 100%'
    );
    // Validate the complete candidate configuration, not each field in
    // isolation: individually acceptable values can combine into a set with no
    // executable tick or step.
    _requirePriceGridHasExecutablePoint(
      _minOrderPrice,
      _maxOrderPrice,
      _tickSize
    );
    _requireQuantityGridHasExecutablePoint(
      _minTradeQty,
      _maxTradeQtyLimit,
      _maxTradeQtyMarket,
      _stepSize
    );

    /// @dev updating price variables
    minPrice = _minOrderPrice;
    maxPrice = _maxOrderPrice;
    tickSize = _tickSize;

    /// @dev updating size/qty vairables
    minQty = _minTradeQty;
    maxQtyLimit = _maxTradeQtyLimit;
    maxQtyMarket = _maxTradeQtyMarket;
    stepSize = _stepSize;

    /// @dev updating market take bound
    mtbLong = _mtbLong;
    mtbShort = _mtbShort;

    /// @dev updating max open notional
    uint128 leverage = BaseMath.baseUInt();
    for (uint128 i = 0; i < _maxOpenNotional.length; i++) {
      maxAllowedOpenNotional[leverage] = _maxOpenNotional[i];
      emit MaxOpenNotionalUpdate(leverage, maxAllowedOpenNotional[leverage]);
      leverage = leverage + BaseMath.baseUInt();
    }
    maxOpenNotionalTierCount = uint128(_maxOpenNotional.length);

    __Ownable_init(_msgSender());
    __Ownable2Step_init();

    emit MinOrderPriceUpdate(_minOrderPrice);
    emit MaxOrderPriceUpdate(_maxOrderPrice);
    emit TickSizeUpdate(tickSize);
    emit MinQuantityUpdate(_minTradeQty);
    emit MaxQuantityLimitUpdate(_maxTradeQtyLimit);
    emit MaxQuantityMarketUpdate(_maxTradeQtyMarket);
    emit StepSizeUpdate(_stepSize);
    emit MTBLongUpdate(_mtbLong);
    emit MTBShortUpdate(_mtbShort);
  }

  //===========================================================//
  //             Configuration Grid Validation (#78)
  //===========================================================//

  /**
   * @dev Smallest positive multiple of `_step` that is at or above `_minimum`,
   * computed in uint256 so the result cannot silently wrap. The caller compares
   * it against a uint128 bound, so an overflowing grid point simply fails that
   * comparison instead of needing its own revert.
   *
   * Uses quotient/remainder rather than
   * `(_minimum + _step - 1) / _step * _step` so nothing intermediate can exceed
   * the range either.
   */
  function _smallestGridPointAtOrAbove(
    uint128 _minimum,
    uint128 _step
  ) private pure returns (uint256) {
    // Both preconditions are enforced by the validators below.
    require(_minimum > 0, 'Evaluator: grid minimum must be > 0');
    require(_step > 0, 'Evaluator: grid step must be > 0');

    uint256 minimum = uint256(_minimum);
    uint256 step = uint256(_step);
    uint256 remainder = minimum % step;
    if (remainder == 0) {
      return minimum;
    }
    return minimum + (step - remainder);
  }

  /**
   * @dev Requires that the candidate quantity configuration contains at least
   * one executable quantity.
   *
   * Every mutable quantity parameter used to be validated in isolation, so an
   * owner could combine individually acceptable values into a set with no valid
   * quantity at all: with minQty = 1e18 and an effective maximum of 2e18, a
   * stepSize of 3e18 leaves no positive multiple inside the permitted range and
   * every quantity check reverts market-wide. Both order-type maximums are
   * covered because the smallest tradable quantity must fit under each of them.
   */
  function _requireQuantityGridHasExecutablePoint(
    uint128 _minQty,
    uint128 _maxQtyLimit,
    uint128 _maxQtyMarket,
    uint128 _stepSize
  ) private pure {
    uint256 smallestTradableQty = _smallestGridPointAtOrAbove(
      _minQty,
      _stepSize
    );
    require(
      smallestTradableQty <= uint256(_maxQtyLimit) &&
        smallestTradableQty <= uint256(_maxQtyMarket),
      'Evaluator: no tradable quantity on the step grid'
    );
  }

  /**
   * @dev Requires that the candidate price configuration contains at least one
   * executable price. The analogous failure to the quantity grid: a tickSize
   * above maxPrice leaves no multiple inside [minPrice, maxPrice].
   */
  function _requirePriceGridHasExecutablePoint(
    uint128 _minPrice,
    uint128 _maxPrice,
    uint128 _tickSize
  ) private pure {
    uint256 smallestTradablePrice = _smallestGridPointAtOrAbove(
      _minPrice,
      _tickSize
    );
    require(
      smallestTradablePrice <= uint256(_maxPrice),
      'Evaluator: no tradable price on the tick grid'
    );
  }

  //===========================================================//
  //                  Checks Verification Methods
  //===========================================================//

  /**
   * @dev verifies that an executed fill quantity sits on the tradable quantity
   * grid: at or above minQty and aligned to stepSize.
   *
   * This check deliberately does NOT apply maxQtyLimit or maxQtyMarket. Those
   * are per-order-type caps on a signed order's own total quantity, checked by
   * verifySignedOrderQuantityCap(). Applying both of them to every fill made
   * the smaller value the effective cap for both order types, and left the
   * signed order total unchecked so an oversized order could execute through a
   * series of individually compliant fills.
   * @param _fillQuantity the executed quantity of a single fill
   * @param _account address blamed in the revert reason
   */
  function verifyFillQuantityGrid(
    uint128 _fillQuantity,
    address _account
  ) public view override {
    Require.that(
      _fillQuantity >= minQty,
      'Trade quantity is < min tradeable quantity',
      _account
    );

    require(
      _fillQuantity % stepSize == 0,
      'Trade quantity does not conforms to allowed step size'
    );
  }

  /**
   * @dev verifies a signed order's own total quantity against the maximum for
   * its order type. A signed order carrying a zero price is a market order and
   * is bound by maxQtyMarket; any other signed order is a limit order and is
   * bound by maxQtyLimit. Callers must classify the order before substituting
   * an execution price into a zero-price market order.
   *
   * SCOPE OF THE ORDER-TYPE CAPS (the one place this policy is written down):
   *
   * `maxQtyMarket` and `maxQtyLimit` bound *signed user orders* only. They are
   * a market-microstructure limit on how much a single user order may ask for,
   * so they are checked against the quantity the user signed. The one
   * signed-order exception is `IsolatedTrader`'s exact full exit (audit #78):
   * a reduce-only order whose fill closes its maker's whole live position
   * skips its own cap and the fill grid (see `IsolatedTrader._verifyOrderFills`).
   *
   * Protocol-generated exits are deliberately outside that scope and are never
   * checked against either cap:
   *   - `IsolatedTrader` forced-liquidation orders (the forced-liquidation
   *     flag), which the protocol generates, unsigned, for a liquidatable
   *     account.
   *   - Every `IsolatedADL` deleveraging trade, which carries no signed order
   *     at all.
   *
   * Applying a user-order cap to those paths would let a market's own
   * configuration block the exits that keep the market solvent: a position
   * above the cap could not be liquidated or deleveraged, exactly when it most
   * needs to be. They are bounded instead by, in `IsolatedTrader`,
   * `fill.quantity <= order.quantity` plus `fill.quantity <= balance.qPos`, and
   * in `IsolatedADL`, the on-chain clamp to `min(maker.qPos, taker.qPos)`.
   * Their per-batch throughput is the off-chain planner's chunk sizing.
   *
   * @param _orderQuantity the total quantity the order was signed for
   * @param _isMarketOrder true when the signed order carried a zero price
   * @param _account address blamed in the revert reason
   */
  function verifySignedOrderQuantityCap(
    uint128 _orderQuantity,
    bool _isMarketOrder,
    address _account
  ) public view override {
    if (_isMarketOrder) {
      Require.that(
        _orderQuantity <= maxQtyMarket,
        'Trade quantity is > max allowed market quantity',
        _account
      );
    } else {
      Require.that(
        _orderQuantity <= maxQtyLimit,
        'Trade quantity is > max allowed limit quantity',
        _account
      );
    }
  }

  /**
   * @dev verifies if the trade price conforms to min/max price and tick size
   * @param _price the price of trade
   */
  function verifyPriceChecks(
    uint128 _price,
    address _maker
  ) public view override {
    verifyMinMaxPriceChecks(_price, _maker);
    require(
      _price % tickSize == 0,
      'Trade price does not conforms to allowed tick size'
    );
  }

  /**
   * @dev verifies if the trade price conforms to min max price checks
   * @param _price the price of trade
   */
  function verifyMinMaxPriceChecks(
    uint128 _price,
    address _maker
  ) public view override {
    Require.that(
      _price >= minPrice,
      'Trade price is < min allowed price',
      _maker
    );
    Require.that(
      _price <= maxPrice,
      'Trade price is > max allowed price',
      _maker
    );
  }

  /**
   * @dev verifies that the trade price is within the market take bound on the
   * one side `_isBuy` selects: at most oracle + bound for a buy, at least
   * oracle - bound for a sell
   * @param _tradePrice the price of trade
   * @param _oraclePrice the price of oracle
   * @param _isBuy buy flag of the order being checked. IsolatedTrader checks
   * the taker's order, and the maker's too when it is a zero-price market order
   * @param _taker account that placed the order being checked; blamed in the
   * revert reason
   */
  function verifyMarketTakeBoundChecks(
    uint128 _tradePrice,
    uint128 _oraclePrice,
    bool _isBuy,
    address _taker
  ) public view override {
    if (binaryMarketPriceBoundsLocked) {
      uint128 binaryAmount = binaryTakeBoundAmountFor(_isBuy, _oraclePrice);
      if (_isBuy) {
        Require.that(
          _tradePrice <= _oraclePrice + binaryAmount,
          'Trade price is > Market Take Bound for long side',
          _taker
        );
      } else {
        Require.that(
          _tradePrice >= _oraclePrice - binaryAmount,
          'Trade price is < Market Take Bound for short side',
          _taker
        );
      }
      return;
    }

    if (_isBuy) {
      Require.that(
        _tradePrice <= (_oraclePrice + _oraclePrice.baseMul(mtbLong)),
        'Trade price is > Market Take Bound for long side',
        _taker
      );
    } else {
      Require.that(
        _tradePrice >= (_oraclePrice - _oraclePrice.baseMul(mtbShort)),
        'Trade price is < Market Take Bound for short side',
        _taker
      );
    }
  }

  /** Return the effective binary execution-bound amount at `_oraclePrice`. */
  function binaryTakeBoundAmountFor(
    bool _isBuy,
    uint128 _oraclePrice
  ) public view override returns (uint128) {
    require(binaryMarketPriceBoundsLocked, 'Evaluator: not binary market');
    require(
      _oraclePrice <= PositionBalanceMath.BINARY_MAX_PRICE,
      'Evaluator: binary oracle out of range'
    );
    uint128 sideCapacity = _isBuy
      ? PositionBalanceMath.BINARY_MAX_PRICE - _oraclePrice
      : _oraclePrice;
    return
      uint128(
        (uint256(sideCapacity) * uint256(binaryTakeRiskFraction)) /
          BaseMath.baseUInt()
      );
  }

  /**
   * @notice Legacy raw trigger-band view retained for interface compatibility.
   * @dev A positive explicit band is returned directly. The zero sentinel
   * returns the historical MTB slot; that is still the effective fraction for
   * non-binary markets, but binary callers must use `triggerBandAmountFor`
   * because the effective directional amount depends on the oracle price.
   * @param _isBuy the buy flag of the order being checked, maker or taker alike
   * @return the stored explicit band or historical side-specific MTB slot
   */
  function triggerBandFor(bool _isBuy) public view override returns (uint128) {
    if (triggerBand != 0) {
      return triggerBand;
    }
    return _isBuy ? mtbLong : mtbShort;
  }

  /**
   * @notice Resolve the actual trigger tolerance in price units.
   * @dev A positive explicit binary band is already an absolute payout-price
   * delta. A binary zero sentinel instead derives the directional amount from
   * `binaryTakeRiskFraction`; non-binary fractions are multiplied by price.
   */
  function triggerBandAmountFor(
    bool _isBuy,
    uint128 _oraclePrice
  ) public view override returns (uint128) {
    if (triggerBand != 0) {
      return
        binaryMarketPriceBoundsLocked
          ? triggerBand
          : _oraclePrice.baseMul(triggerBand);
    }
    if (binaryMarketPriceBoundsLocked) {
      return binaryTakeBoundAmountFor(_isBuy, _oraclePrice);
    }
    return _oraclePrice.baseMul(_isBuy ? mtbLong : mtbShort);
  }

  /**
   * @dev verifies if the provided account has open notional <= maximum allowed
   * open notional for current leverage. A disabled tier (see
   * `_openNotionalCapExcess`) fails this check for any position with nonzero
   * open notional.
   * @param _account address of account
   * @param _balance Position balance of the account
   * @param _oraclePrice Current oracle price used to compute open notional
   */
  function verifyOpenNotionalForAccount(
    address _account,
    Types.PositionBalance memory _balance,
    uint128 _oraclePrice
  ) public view override {
    // Precondition: callers set a nonzero mro (1e18 / leverage) before this
    // check. Guard the division below so a zero mro reverts clearly instead of
    // an opaque division-by-zero panic.
    Require.that(_balance.mro > 0, 'Evaluator: mro must be > 0', _account);

    Require.that(
      _openNotionalCapExcess(_account, _balance, _oraclePrice) == 0,
      'Open notional for selected leverage > max allowed open notional',
      _account
    );
  }

  /**
   * @dev verifies an account's before -> after position transition against the
   * open-notional cap of its selected leverage tier.
   *
   * - A risk-increasing transition (quantity growth, a flip, or higher
   *   selected leverage) must land fully inside an enabled tier: zero excess.
   *   Growing an already-over-cap position, or opening any exposure in a
   *   disabled tier, is rejected.
   * - Anything else (same-side reductions, full closes, leverage reductions)
   *   only has to not increase the excess. That is what lets a position whose
   *   tier was tightened or disabled after it was opened still be reduced,
   *   closed, or moved to lower leverage.
   *
   * Risk-reducing paths that never touch the cap at all (reduce-only fills)
   * intentionally do not call this verifier.
   */
  function verifyOpenNotionalTransitionForAccount(
    address _account,
    Types.PositionBalance memory _beforeBalance,
    Types.PositionBalance memory _afterBalance,
    uint128 _oraclePrice
  ) public view override {
    uint128 afterExcess = _openNotionalCapExcess(
      _account,
      _afterBalance,
      _oraclePrice
    );

    if (
      PositionBalanceMath.isRiskIncreasingTransition(
        _beforeBalance,
        _afterBalance
      )
    ) {
      Require.that(
        afterExcess == 0,
        'Open notional for selected leverage > max allowed open notional',
        _account
      );
      return;
    }

    uint128 beforeExcess = _openNotionalCapExcess(
      _account,
      _beforeBalance,
      _oraclePrice
    );

    Require.that(
      afterExcess <= beforeExcess,
      'Open notional for selected leverage > max allowed open notional',
      _account
    );
  }

  /**
   * @dev Returns how far a position's open notional sits above the cap of its
   * selected leverage tier.
   *
   * A tier is enabled only when it is inside the configured range
   * (1x .. maxOpenNotionalTierCount) AND carries a nonzero cap. Missing,
   * cleared, and zero-cap tiers are disabled, not unlimited: a disabled tier
   * reports the position's whole open notional as excess, so every
   * risk-increasing update in it fails while reductions and closes still go
   * through. There is no "unlimited tier" interpretation; an intentionally
   * uncapped tier would need its own named feature.
   *
   * This is also why an Evaluator proxy upgraded before `maxOpenNotionalTierCount`
   * existed reads 0 and therefore treats every tier as disabled. That is
   * fail-closed on purpose — the rollout republishes each market's permitted
   * tier list with `setMaxOpenNotional` before trading resumes, rather than
   * guessing what the mapping already held.
   */
  function _openNotionalCapExcess(
    address _account,
    Types.PositionBalance memory _balance,
    uint128 _oraclePrice
  ) private view returns (uint128) {
    if (_balance.qPos == 0) {
      return 0;
    }

    // Precondition: live positions have a nonzero mro (1e18 / leverage).
    Require.that(_balance.mro > 0, 'Evaluator: mro must be > 0', _account);

    uint128 openNotional = _balance.qPos.baseMul(_oraclePrice);
    uint128 cap = _enabledOpenNotionalCap(_roundedLeverage(_balance.mro));
    if (openNotional <= cap) {
      return 0;
    }
    return openNotional - cap;
  }

  /**
   * @dev Cap for a leverage tier, or 0 when that tier is disabled.
   * @param _leverage whole leverage in 18-decimal units (1e18 == 1x)
   */
  function _enabledOpenNotionalCap(
    uint128 _leverage
  ) private view returns (uint128) {
    uint128 tierIndex = _leverage / BaseMath.baseUInt();
    if (tierIndex == 0 || tierIndex > maxOpenNotionalTierCount) {
      return 0;
    }
    return maxAllowedOpenNotional[_leverage];
  }

  function _roundedLeverage(uint128 mro) private pure returns (uint128) {
    // convert mro to leverage (1/mro)
    uint128 leverage = BaseMath.baseUInt().baseDiv(mro);

    uint128 remainder = leverage % BaseMath.baseUInt();

    if (remainder > HALF_BASE_UINT) {
      return BaseMath.ceil(leverage, BaseMath.baseUInt());
    }
    return (leverage / BaseMath.baseUInt()) * BaseMath.baseUInt();
  }

  //===========================================================//
  //                         SETTERS
  //===========================================================//

  /**
   * @notice Changes minimum trade price to the provided one
   * @param _price  The new minimum trade price
   */
  function setMinOrderPrice(uint128 _price) public onlyOwner {
    require(
      !binaryMarketPriceBoundsLocked,
      'Evaluator: binary price bounds locked'
    );
    require(_price > 0, 'Minimum order price must be > 0');
    require(
      _price < maxPrice,
      'Minimum trade price must be < maximum trade price'
    );
    _requirePriceGridHasExecutablePoint(_price, maxPrice, tickSize);
    minPrice = _price;
    emit MinOrderPriceUpdate(_price);
  }

  /**
   * @notice Changes maximum trade price to the provided one
   * @param _price  The new maximum trade price
   */
  function setMaxOrderPrice(uint128 _price) public onlyOwner {
    require(
      !binaryMarketPriceBoundsLocked,
      'Evaluator: binary price bounds locked'
    );
    require(_price > minPrice, 'Maximum trade price must be > min trade price');
    _requirePriceGridHasExecutablePoint(minPrice, _price, tickSize);
    maxPrice = _price;
    emit MaxOrderPriceUpdate(_price);
  }

  /**
   * @notice Permanently locks a binary market's price bounds at [1 wei, 1e18].
   * @dev Existing markets call this once during their upgrade campaign; new
   * binary deployments call it during deploy setup.
   */
  function lockBinaryMarketPriceBounds() public onlyOwner {
    require(
      !binaryMarketPriceBoundsLocked,
      'Evaluator: binary price bounds already locked'
    );
    require(
      minPrice == PositionBalanceMath.BINARY_MIN_PRICE &&
        maxPrice == PositionBalanceMath.BINARY_MAX_PRICE,
      'Evaluator: not binary price bounds'
    );
    binaryMarketPriceBoundsLocked = true;
    emit BinaryMarketPriceBoundsLocked();
  }

  /** Configure or tighten the complement-symmetric binary execution bound. */
  function setBinaryTakeRiskFraction(uint128 _riskFraction) public onlyOwner {
    require(binaryMarketPriceBoundsLocked, 'Evaluator: not binary market');
    require(
      _riskFraction > 0 && _riskFraction <= BaseMath.baseUInt(),
      'Evaluator: binary risk fraction out of range'
    );
    if (binaryTakeRiskFraction != 0) {
      require(
        _riskFraction <= binaryTakeRiskFraction,
        'Evaluator: binary risk fraction cannot increase'
      );
    }
    binaryTakeRiskFraction = _riskFraction;
    emit BinaryTakeRiskFractionUpdate(_riskFraction);
  }

  /**
   * @notice Changes Tick Size to the provided one
   * @dev the size is represented in 18 decimals
   * 1 tick size is represented as 1 * 1e18, implying no decimals are allowed
   * 0.01 tick size is represented as  0.01 * 1e18, implying two decimal points are allowed
   * @param _size The new tick size
   */
  function setTickSize(uint128 _size) public onlyOwner {
    require(_size > 0, 'Tick Size Must be > 0');
    _requirePriceGridHasExecutablePoint(minPrice, maxPrice, _size);
    tickSize = _size;
    emit TickSizeUpdate(_size);
  }

  /**
   * @notice Changes Minimum Quantity to the provided one
   * @param _quantity  The new minimum quantity
   */
  function setMinQty(uint128 _quantity) public onlyOwner {
    require(
      _quantity < maxQtyLimit && _quantity < maxQtyMarket,
      'Minimum trade quantity must be < max trade quantity'
    );
    require(_quantity > 0, 'Minimum trade quantity must be > 0');
    _requireQuantityGridHasExecutablePoint(
      _quantity,
      maxQtyLimit,
      maxQtyMarket,
      stepSize
    );
    minQty = _quantity;
    emit MinQuantityUpdate(_quantity);
  }

  /**
   * @notice Changes Maximum Limit Quantity to the provided one
   * @param _quantity The new maximum Limit Quantity
   */
  function setMaxQtyLimit(uint128 _quantity) public onlyOwner {
    require(
      _quantity > minQty,
      'Maximum Limit Trade quantity must be > minimum trade quantity'
    );
    _requireQuantityGridHasExecutablePoint(
      minQty,
      _quantity,
      maxQtyMarket,
      stepSize
    );
    maxQtyLimit = _quantity;
    emit MaxQuantityLimitUpdate(_quantity);
  }

  /**
   * @notice Changes Maximum Market Quantity to the provided one
   * @param _quantity The new maximum Marktet Quantity
   */
  function setMaxQtyMarket(uint128 _quantity) public onlyOwner {
    require(
      _quantity > minQty,
      'Maximum Market Trade quantity must be > minimum trade quantity'
    );
    _requireQuantityGridHasExecutablePoint(
      minQty,
      maxQtyLimit,
      _quantity,
      stepSize
    );
    maxQtyMarket = _quantity;
    emit MaxQuantityMarketUpdate(_quantity);
  }

  /**
   * @notice Changes Step Size to the provided one
   * @dev 1 size is represented as 1 * 1e18, implying no decimals are allowed
   * 0.01 size is represented as  0.01 * 1e18, implying two decimal points are allowed
   * @param _size The new Step size
   */
  function setStepSize(uint128 _size) public onlyOwner {
    require(_size > 0, 'Step Size must be > 0');
    _requireQuantityGridHasExecutablePoint(
      minQty,
      maxQtyLimit,
      maxQtyMarket,
      _size
    );
    stepSize = _size;
    emit StepSizeUpdate(_size);
  }

  /**
   * @notice Tightens Market Take Bound for Long Trades to the provided one
   * @param _value The new long market bound value
   */
  function setMTBLong(uint128 _value) public onlyOwner {
    require(_value > 0, 'Market Take Bound for long trades must be > 0');
    require(
      _value < BaseMath.baseUInt(),
      'Market Take Bound for long trades must be < 100%'
    );
    require(
      _value <= mtbLong,
      'Market Take Bound for long trades cannot increase'
    );
    mtbLong = _value;
    emit MTBLongUpdate(_value);
  }

  /**
   * @notice Tightens Market Take Bound for Short Trades to the provided one
   * @param _value The new Short market bound value
   */
  function setMTBShort(uint128 _value) public onlyOwner {
    require(_value > 0, 'Market Take Bound for short trades must be > 0');
    require(
      _value < BaseMath.baseUInt(),
      'Market Take Bound for short trades must be < 100%'
    );
    require(
      _value <= mtbShort,
      'Market Take Bound for short trades cannot increase'
    );

    mtbShort = _value;
    emit MTBShortUpdate(_value);
  }

  /**
   * @notice Sets the audit-#50 trigger band. It is an e18 fraction of oracle
   * price for non-binary markets and an absolute payout-price delta for binary
   * markets. Zero restores the market-take-bound default.
   * @dev Unlike the take bounds this may move in both directions. The band is
   * a tolerance for mark-vs-oracle divergence, not a user-facing execution
   * promise: a market whose oracle tightens should be able to tighten the band,
   * and one whose oracle is later found noisier must be able to widen it again
   * without an implementation upgrade. A full-width band—100% of oracle on a
   * non-binary market, or the full payout range on a binary market—is no longer
   * a meaningful trigger tolerance.
   * @param _value the new raw band, or zero to use the take bound
   */
  function setTriggerBand(uint128 _value) public onlyOwner {
    require(
      _value < BaseMath.baseUInt(),
      'Trigger band must be < 100% of oracle price'
    );
    triggerBand = _value;
    emit TriggerBandUpdate(_value);
  }

  /**
   * @notice allows admin to set max allowed open notional for selected mro
   * @param _maxLimit the max allowed open-notional array. Each index corresponds to leverage
   */
  function setMaxOpenNotional(uint128[] memory _maxLimit) public onlyOwner {
    uint128 newCount = uint128(_maxLimit.length);
    uint128 leverage = BaseMath.baseUInt();
    for (uint128 i = 0; i < newCount; i++) {
      maxAllowedOpenNotional[leverage] = _maxLimit[i];
      emit MaxOpenNotionalUpdate(leverage, maxAllowedOpenNotional[leverage]);
      leverage = leverage + BaseMath.baseUInt();
    }

    // Clear any higher-leverage tiers a previous, longer list set, so shrinking
    // the tier list doesn't leave stale caps in place. `leverage` already points
    // at the first tier past the new list. Cleared tiers are DISABLED, not
    // uncapped: shrinking the list forbids those leverages for new and growing
    // exposure while leaving existing positions in them reducible and
    // closable. A zero entry inside the list disables that tier the same way.
    // Entries written before an upgrade added `maxOpenNotionalTierCount` are
    // not cleared here; they stay inert because `_enabledOpenNotionalCap`
    // ignores tiers above the count.
    for (uint128 i = newCount; i < maxOpenNotionalTierCount; i++) {
      maxAllowedOpenNotional[leverage] = 0;
      emit MaxOpenNotionalUpdate(leverage, 0);
      leverage = leverage + BaseMath.baseUInt();
    }

    maxOpenNotionalTierCount = newCount;
  }
}
