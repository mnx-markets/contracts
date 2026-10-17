// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

//utils
import {Ownable2StepUpgradeable} from '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {BlockContext} from './utils/BlockContext.sol';

// interfaces
import {IGuardian} from './interfaces/IGuardian.sol';
import {IFundingOracle} from './interfaces/IFundingOracle.sol';
import {IMarginBank} from './interfaces/IMarginBank.sol';
import {IPerpetual} from './interfaces/IPerpetual.sol';

// libraries
import {Types} from './libraries/Types.sol';

/**
 * @title Guardian
 * @author MNX Markets <help@mnx.fi>
 * @notice Guardian contract, able to control certain aspects of the protocol including:
 * 1. starting/stopping trade on a perpetual
 * 2. starting/stopping withdrawal of funds from margin bank
 * 3. switching a market's funding mode (the rate is supplied off-chain in both)
 * Will become obselete once governance is live
 *
 * @notice That list is exhaustive. Guardian has NO price-oracle pause control,
 * and deliberately does not: halting price updates would mark positions at a
 * stale price and stop liquidations from firing, which is strictly worse than
 * the trading pause above, and `Perpetual.oracleMaxStalenessSeconds` would then
 * revert trades anyway. A misbehaving price updater is bounded by the price
 * oracle's per-update cap (`maxUpdateBps`, or `riskFractionE18` on a binary
 * oracle) and handled by revoking that updater — not
 * by pausing the feed. A dead `POStatusUpdate` event that advertised such a
 * control was removed here (audit issue #85); do not reintroduce it.
 *
 * @dev Authority model — three independent roles:
 *
 * - `owner` (Ownable2Step): the only role that can rotate the other two. It
 *   holds no emergency power of its own.
 * - `guardianOperator`: the hot emergency key. Pauses/resumes trading and
 *   withdrawals, and is also accepted by the funding-status check.
 * - `fundingStatusOperator`: funding status only. May be the zero address,
 *   which deliberately means "no separate funding-only role"; the guardian
 *   operator can still toggle funding status.
 *
 * These roles are independent on purpose. Transferring and accepting ownership
 * moves `owner()` and nothing else, so a retired deployment key does NOT lose
 * its emergency authority just because ownership moved to a multisig. Use
 * {setEmergencyRoles} to move both emergency roles in one transaction as part
 * of the handoff. `renounceOwnership` is disabled: an active guardian operator
 * with no owner able to rotate it is not a state this contract may enter.
 *
 * @dev The contract is made upgradable using openzeppelin upgrades-pluging, don't change
 * the order of variables. Read more: https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies
 */
contract Guardian is
  IGuardian,
  Ownable2StepUpgradeable,
  ReentrancyGuard,
  BlockContext
{
  //
  // EVENTS
  //

  /// @notice Emitted when the guardian operator is updated. Carries the exact
  /// previous and new values so a handoff can be audited from logs alone.
  event GuardianOperatorUpdate(
    address indexed previousGuardianOperator,
    address indexed newGuardianOperator
  );

  /// @notice Emitted when the funding-status operator is updated. Carries the
  /// exact previous and new values.
  event FundingStatusOperatorUpdate(
    address indexed previousFundingStatusOperator,
    address indexed newFundingStatusOperator
  );

  /// @notice Emitted when trading is enabled or disabled for a certain market
  event TradingStatusUpdate(address marketAddress, Types.GuardianStatus status);

  /// @notice Emitted when a market's funding oracle switches funding mode.
  /// The caller attributes the toggle (guardian operator vs
  /// funding-status operator) so off-chain automation can recover ownership
  /// from history.
  event FRStatusUpdate(
    address indexed fundingOracle,
    Types.GuardianStatus status,
    address caller
  );

  /// @notice Emitted when emergency funding disable could not settle first
  event FundingStatusSettlementSkipped(
    address fundingOracle,
    address fundingProvider,
    bytes reason
  );

  /// @notice Emitted when withdrawal is enabled or disabled from margin bank
  event WithdrawalStatusUpdate(
    address marketAddress,
    Types.GuardianStatus status
  );

  //**********************************************************//
  //    The below state variables can not change the order    //
  //**********************************************************//

  /// @notice The address of the guardian account
  /// the guardian is used to enable/disable trading and withdrawals and to switch
  /// funding modes
  address public override guardianOperator;

  uint256[50] private __gap;

  //**********************************************************//
  //    The above state variables can not change the order    //
  //**********************************************************//

  //◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤ add state variables below ◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤//

  /// @notice Operator allowed to toggle funding status without full Guardian powers
  address public override fundingStatusOperator;

  //◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣ add state variables above ◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣//

  /**
   * Throws if called by any account other than the guardian
   */
  modifier onlyGuardianOperator() {
    require(
      guardianOperator == _msgSender(),
      'Guardian: caller is not the guardian operator'
    );
    _;
  }

  /**
   * Throws if called by an account that cannot toggle funding status
   * (neither the guardian operator nor the funding-status operator)
   */
  modifier onlyFundingStatusOperator() {
    require(
      guardianOperator == _msgSender() || fundingStatusOperator == _msgSender(),
      'Guardian: caller cannot set funding status'
    );
    _;
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  /**
   * @notice Initializes a fresh Guardian with explicit, independent roles.
   * @dev No role is derived from `msg.sender`: a deployment key that is not
   * meant to hold emergency authority must never be handed it implicitly.
   * @param _initialOwner The owner, the only role that can rotate the other
   * two. The zero address is rejected by `__Ownable_init`.
   * @param _initialGuardianOperator The hot emergency key. Must be non-zero:
   * a Guardian with no operator cannot pause trading or withdrawals.
   * @param _initialFundingStatusOperator The funding-only operator. The zero
   * address is allowed and deliberately means the separate funding-only role
   * is disabled; the guardian operator can still toggle funding status.
   */
  function initialize(
    address _initialOwner,
    address _initialGuardianOperator,
    address _initialFundingStatusOperator
  ) public initializer {
    // Runs first so a zero owner reverts with OwnableInvalidOwner before any
    // role is written.
    __Ownable_init(_initialOwner);
    __Ownable2Step_init();

    _setGuardianOperator(_initialGuardianOperator);
    _setFundingStatusOperator(_initialFundingStatusOperator);
  }

  //===========================================================//
  //                         SETTERS
  //===========================================================//

  /**
   * @notice Sets a new guardian operator.
   * @param _newGuardianOperator The new guardian operator. Must be non-zero.
   */
  function setGuardianOperator(
    address _newGuardianOperator
  ) external override onlyOwner nonReentrant {
    _setGuardianOperator(_newGuardianOperator);
  }

  /**
   * @notice Sets an operator that can toggle funding status only.
   * @param _newOperator The new funding-status operator. Use the zero address
   * to disable the separate funding-only role.
   */
  function setFundingStatusOperator(
    address _newOperator
  ) external override onlyOwner nonReentrant {
    _setFundingStatusOperator(_newOperator);
  }

  /**
   * @notice Moves both emergency roles in a single transaction.
   * @dev This is the handoff primitive. Rotating the two roles in separate
   * transactions leaves a window where the retired key still holds one of
   * them; this cannot half-apply.
   * @param _newGuardianOperator The new guardian operator. Must be non-zero.
   * @param _newFundingStatusOperator The new funding-status operator. Use the
   * zero address to disable the separate funding-only role.
   */
  function setEmergencyRoles(
    address _newGuardianOperator,
    address _newFundingStatusOperator
  ) external override onlyOwner nonReentrant {
    _setGuardianOperator(_newGuardianOperator);
    _setFundingStatusOperator(_newFundingStatusOperator);
  }

  /**
   * @notice Renouncing ownership is disabled.
   * @dev Unconditional on purpose. `guardianOperator` is non-zero on every
   * write path ({initialize}, {setGuardianOperator}, {setEmergencyRoles}), so
   * a Guardian always has a live emergency key. Renouncing would leave that
   * key able to pause and resume the exchange with nobody able to rotate it,
   * which is unrecoverable.
   *
   * Written as a plain revert rather than a `require` on
   * `guardianOperator == 0`: that condition can never hold, so stating it
   * would read as conditionally renounceable, and it would silently become
   * reachable if the non-zero guard were ever relaxed.
   */
  function renounceOwnership() public view override onlyOwner {
    revert('Guardian: renouncing ownership is disabled');
  }

  function _setGuardianOperator(address _newGuardianOperator) private {
    require(
      _newGuardianOperator != address(0),
      'Guardian: guardian operator is the zero address'
    );
    address previousGuardianOperator = guardianOperator;
    guardianOperator = _newGuardianOperator;
    emit GuardianOperatorUpdate(
      previousGuardianOperator,
      _newGuardianOperator
    );
  }

  function _setFundingStatusOperator(address _newOperator) private {
    address previousFundingStatusOperator = fundingStatusOperator;
    fundingStatusOperator = _newOperator;
    emit FundingStatusOperatorUpdate(
      previousFundingStatusOperator,
      _newOperator
    );
  }

  /**
   * @dev sets the status of trading on/off
   * @param _perpetual represents address of Perpetual contract address for a market
   * @param _newStatus status of trading for this market. If not allowed then no new trades can be performed
   */
  function setTradingStatus(
    address _perpetual,
    Types.GuardianStatus _newStatus
  ) external override onlyGuardianOperator nonReentrant {
    IPerpetual(_perpetual).setTradingStatus(_newStatus);
    emit TradingStatusUpdate(_perpetual, _newStatus);
  }

  /**
   * @dev sets the funding rate status on-chain/off-chain
   * @param _fundingOracle represents address of FundingOracle contract address for a market
   * @param _newStatus ALLOWED selects the on-chain funding mode; any other
   * status selects the off-chain mode. The rate is supplied off-chain in both
   * modes, and a switch zeroes the current rate until a replacement is installed.
   */
  function setFundingRateStatus(
    address _fundingOracle,
    Types.GuardianStatus _newStatus
  ) external override onlyFundingStatusOperator nonReentrant {
    bool wasAllowed = IFundingOracle(_fundingOracle).isFundingRateAllowed();
    bool shouldAllow = _newStatus == Types.GuardianStatus.ALLOWED;
    if (wasAllowed != shouldAllow) {
      address fundingProvider = IFundingOracle(_fundingOracle).provider();
      if (fundingProvider.code.length > 0) {
        if (shouldAllow) {
          IPerpetual(fundingProvider).updateGlobalIndex();
        } else {
          (
            bool settled,
            bytes memory settlementRevertData
          ) = fundingProvider.call(
              abi.encodeWithSelector(IPerpetual.updateGlobalIndex.selector)
            );
          if (!settled) {
            emit FundingStatusSettlementSkipped(
              _fundingOracle,
              fundingProvider,
              settlementRevertData
            );
          }
        }
      } else {
        require(
          !shouldAllow && IFundingOracle(_fundingOracle).getFundingRate() == 0,
          'Guardian: funding provider is not contract'
        );
      }
    }

    IFundingOracle(_fundingOracle).setFundingRateStatus(_newStatus);
    emit FRStatusUpdate(_fundingOracle, _newStatus, _msgSender());
  }

  /**
   * @dev enables/disables withdrawals from a MarginBank. The status is
   * bank-wide: it gates every withdrawal from that bank, by users and by
   * system-account controllers such as the LiquidityVault, for all markets.
   * @param _marginBank address of the MarginBank contract
   * @param _newStatus ALLOWED enables withdrawals; NOT_ALLOWED disables them
   */
  function setWithdrawalStatus(
    address _marginBank,
    Types.GuardianStatus _newStatus
  ) external override onlyGuardianOperator nonReentrant {
    IMarginBank(_marginBank).setWithdrawalStatus(_newStatus);
    emit WithdrawalStatusUpdate(_marginBank, _newStatus);
  }

  //===========================================================//
  //                      GETTERS
  //===========================================================//

  /**
   * @param _perpetual address of the Perpetual contract for a given market, returns true
   * while its Guardian trading status is ALLOWED. NOT_ALLOWED blocks every trade, including
   * liquidations; true alone does not mean trades are accepted (a delisted or not-yet-started
   * market still rejects them)
   */
  function isTradingAllowed(
    address _perpetual
  ) external view override returns (bool) {
    return IPerpetual(_perpetual).isTradingAllowed();
  }

  /**
   * @param _fundingOracle address of the FundingOracle contract for a given market, returns true
   * while the market is in the on-chain funding mode (status ALLOWED)
   */
  function isFundingRateAllowed(
    address _fundingOracle
  ) external view override returns (bool) {
    return IFundingOracle(_fundingOracle).isFundingRateAllowed();
  }

  /**
   * @param _marginBank address of the MarginBank contract, returns true if
   * that bank's withdrawal status (bank-wide, not per market) is ALLOWED else false
   */
  function isWithdrawalAllowed(
    address _marginBank
  ) external view override returns (bool) {
    return IMarginBank(_marginBank).isWithdrawalAllowed();
  }
}
