// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

// utils
import {Ownable2StepUpgradeable} from '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {SafeCast} from '@openzeppelin/contracts/utils/math/SafeCast.sol';
import {BaseRelayRecipient} from './utils/BaseRelayRecipient.sol';
import {BlockContext} from './utils/BlockContext.sol';

// interfaces
import {IFundingOracle} from './interfaces/IFundingOracle.sol';
import {IMarginBank} from './interfaces/IMarginBank.sol';
import {ITrader} from './interfaces/ITrader.sol';
import {IEvaluator} from './interfaces/IEvaluator.sol';
import {IGuardian} from './interfaces/IGuardian.sol';
import {IMarginMath} from './interfaces/IMarginMath.sol';
import {IPerpetual} from './interfaces/IPerpetual.sol';
import {IAccountManager} from './interfaces/IAccountManager.sol';
import {ISignatureVerifier} from './interfaces/ISignatureVerifier.sol';
import {IBackstopVault} from './interfaces/IBackstopVault.sol';
import {IOracleFactory} from './interfaces/IOracleFactory.sol';
import {AggregatorV3Interface as IPriceOracle} from '@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol';

// maths
import {BaseMath} from './maths/BaseMath.sol';
import {PositionBalanceMath} from './maths/PositionBalanceMath.sol';

// libraries
import {Types} from './libraries/Types.sol';
import {Require} from './libraries/Require.sol';
import {TypedSignature} from './libraries/TypedSignature.sol';
import {PackedStateLib} from './libraries/PackedStateLib.sol';

/**
 * @title Perpetual
 * @author MNX Markets <help@mnx.fi>
 * @notice Represents a perpetual being traded on mnx exchange. Each perpetual is pegged against the real
 * world asset via the price provided by its factory-minted price oracle.
 * @dev The contract is made upgradable using openzeppelin upgrades-pluging, don't change
 * the order of variables. Read more: https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies
 */
contract Perpetual is
  IPerpetual,
  Ownable2StepUpgradeable,
  // OZ 5.6.1 is @custom:stateless and uses a fixed namespaced slot;
  // issue #32 tests pin these proxy-layout assumptions.
  ReentrancyGuard,
  BaseRelayRecipient,
  BlockContext
{
  using BaseMath for uint128;
  using BaseMath for int256;
  using PositionBalanceMath for Types.PositionBalance;
  using PackedStateLib for Types.PackedAccountState;

  /// @notice The factory whose `isFactoryOracle` registry this implementation
  /// accepts: oracles it minted plus those of its immutable predecessor
  /// factories. The value lives in implementation bytecode rather than proxy
  /// storage, so it has no setter and changing it requires a reviewed
  /// Perpetual implementation upgrade.
  /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
  IOracleFactory public immutable ORACLE_FACTORY;

  //
  // EVENTS
  //

  /// @notice Emitted when perpetual is delisted by admin
  event PerpetualDelisted(uint128 settlementPrice);

  /// @notice Emitted when a pending delist is aborted by the owner before
  /// the settlement quarantine window elapses. After this event the delist
  /// fields and aggregate claim state are reset and the 'P1' gate lifts; state
  /// changed while delisted is not rolled back (bankruptcy flags witnessed at
  /// the frozen terms keep the 'P87' gate armed until cleared).
  event PerpetualDelistAborted(uint128 abortedAt);

  /// @notice Emitted once per account newly registered for delist claims
  /// (audit #41). Re-registering an already-registered account emits nothing.
  event DelistClaimRegistered(
    address indexed account,
    uint128 claimE18Raw,
    uint128 registeredCount,
    uint256 registeredTotalE18Raw
  );

  /// @notice Emitted when the owner attests that the complete frozen claimant
  /// population has been registered for the current delist epoch. The normal
  /// complete-population path locks only after this event; an unfinalized
  /// positive fallback set may lock at the original close boundary.
  event DelistClaimPopulationFinalized(
    uint128 indexed epoch,
    uint128 registeredCount,
    uint256 registeredTotalE18Raw,
    uint128 finalizedAt
  );

  /// @notice Emitted exactly once, when the pro-rata payout ratio is locked.
  /// `ratioE18 == 1e18` is the funded (no-op) outcome. `retainedFeeE18Raw` is
  /// what survived fee subordination; `feesAbsorbedE18Raw` is the loss
  /// protocol fees took before any user claim was reduced.
  event DelistClaimRatioLocked(
    uint128 ratioE18,
    uint256 distributablePotE18Raw,
    uint256 registeredTotalE18Raw,
    uint128 retainedFeeE18Raw,
    uint128 feesAbsorbedE18Raw
  );

  /// @notice Emitted per account settled against the locked ratio.
  /// `grossClaimE18Raw` is the registered snapshot, `paidE18Raw` the
  /// ratio'd payout actually transferred.
  event DelistClaimSettled(
    address indexed account,
    uint128 grossClaimE18Raw,
    uint128 paidE18Raw,
    uint128 ratioE18
  );

  /// @notice Emitted when the post-settlement residual is swept to the
  /// backstop vault.
  event DelistClaimResidualSwept(
    address indexed backstopVault,
    uint128 amountE18Raw
  );

  /// @notice Emitted when settlement amount is applied to account
  event AccountSettlementUpdate(
    address indexed account,
    Types.PositionBalance balance,
    bool settlementIsPositive,
    uint128 formulaAmount,
    uint128 marginPortion,
    uint128 profitPortion,
    uint128 forgiven,
    int256 appliedFundingIndex,
    uint128 price,
    int256 fundingRate,
    uint128 timestamp
  );

  /// @notice Emitted when an account withdraws using closePosition
  event PositionClosed(
    address indexed account,
    uint128 amount,
    uint128 timestamp
  );

  /// @notice Emitted when trading on perpetual starts
  event TradingStarted(uint128 startTime);

  /// @notice Emitted when trading on perpetual stops
  event TradingStopped(uint128 stopTime);

  /// @notice Emitted when settlement operator status is updated
  event SettlementOperatorUpdate(address operator, bool approved);

  /// @notice Emitted when trader contract status is updated
  event TradeContractUpdate(address tradeContract, bool approved);

  /// @notice Emitted once per fill, for ADL batches (trader flag 3) only. Book
  /// liquidations settle in regular batches and emit BatchTradeExecuted and
  /// ForcedBookLiquidationFill instead.
  event TradeExecuted(
    address indexed maker,
    address indexed taker,
    bytes32 makerOrderHash,
    bytes32 takerOrderHash,
    uint128 makerFee,
    uint128 takerFee,
    int256 makerPnl,
    int256 takerPnl,
    int256 makerFundsFlow,
    int256 takerFundsFlow,
    int256 makerMarginDelta,
    int256 takerMarginDelta,
    uint128 tradeQuantity,
    uint128 price,
    bool isBuy // from the perspective of taker
  );

  /// @notice Emitted once per user per batch with aggregated trade data
  /// @dev Minimal payload for gas efficiency - per-order breakdown stored off-chain
  /// @param firstFillIsLong direction of this user's FIRST fill in the batch, and
  ///        nothing more. It is deliberately NOT net traded direction and NOT
  ///        final position direction: a user with fills on both sides of the same
  ///        batch can end it flat or on the opposite side from the first fill, and
  ///        a boolean cannot represent a flat batch at all. Consumers that need
  ///        net traded direction must sum the signed per-fill quantities from
  ///        their own fill records; consumers that need the resulting position
  ///        must read {AccountPositionUpdate} or {getAccountBalance}.
  event BatchTradeExecuted(
    address indexed trader,
    uint128 totalQuantity, // Total quantity traded in this batch
    uint128 totalFee, // Total fees paid
    int256 totalPnl, // Total realized PnL
    int256 fundsFlow, // Net margin flow (positive = user pays, negative = user receives)
    int256 marginDelta, // Net position margin change
    uint128 price, // Batch clearing price
    bool firstFillIsLong // Direction of this user's first fill only
  );

  /// @notice Emitted once for each forced book-liquidation side of a regular trade
  /// @dev Sparse attribution event. fundsFlow uses the same sign convention as
  ///      BatchTradeExecuted: positive means funds leave the account balance.
  event ForcedBookLiquidationFill(
    address indexed account,
    bytes32 indexed orderHash,
    int256 fundsFlow
  );

  /// @notice Emitted when a position of account is updated
  event AccountPositionUpdate(
    address indexed account,
    address sender,
    Types.PositionBalance position,
    Types.PositionBalance prevPosition,
    Action action,
    int256 index,
    uint128 timestamp,
    int256 marginDelta
  );

  /// @notice Emitted when price oracle address is updated
  event PriceOracleUpdate(address oracle);

  /// @notice Transition evidence for every `setOracle` call. Emitted just
  /// before the existing `PriceOracleUpdate`, which is unchanged, so existing
  /// consumers keep seeing the same facts in the same transaction.
  /// @param previousOracle Incumbent feed, or the zero address on the first
  /// installation.
  /// @param newOracle Replacement feed now backing the market.
  /// @param previousAnswer Incumbent's last answer when the movement
  /// comparison ran, and 0 whenever it was skipped — no incumbent, a
  /// same-address re-point, or a halted market. A zero here always means "no
  /// comparison", never "the incumbent reported zero".
  /// @param newAnswer Replacement's current answer, as validated by
  /// `_requireValidOracle`.
  /// @param appliedMaxUpdateBps Stricter of the two feeds' movement caps that
  /// the transition was measured against, or 0 when no comparison ran.
  /// @param continuityProven True when the transition is known not to be
  /// discontinuous — either the movement comparison ran and passed, or there
  /// was nothing to keep continuous. False when the market was halted and the
  /// comparison was therefore skipped; that is the on-chain marker that this
  /// market needs the stopped-market checkpoint process before trading
  /// resumes. Indexed so that marker can be filtered for directly.
  event PriceOracleReplaced(
    address indexed previousOracle,
    address indexed newOracle,
    uint256 previousAnswer,
    uint256 newAnswer,
    uint256 appliedMaxUpdateBps,
    bool indexed continuityProven
  );

  /// @notice Emitted when evaluator address is updated
  event EvaluatorUpdate(address evaluator);

  /// @notice Emitted when oracle freshness enforcement is updated
  event OracleMaxStalenessUpdate(uint128 maxStalenessSeconds);

  /// @notice Emitted when global-index batch freshness enforcement is updated
  event MaxBatchesPerGlobalIndexUpdate(uint128 maxBatches);

  /// @notice Emitted when the binary-future market flag is initialized.
  event BinaryFutureMarketFlagInitialized(bool isBinaryFutureMarket);

  /// @notice Emitted when the one-way full-collateral bound exemption is set.
  event BinaryFullCollateralBoundsEligibilityInitialized(bool eligible);

  /// @notice Emitted when funding oracle address is updated
  event FundingOracleUpdate(address funder);

  /// @notice Emitted when fee pool address is updated
  event FeePoolUpdate(address feePool);

  /// @notice Emitted when market order (taker) fee is adjusted
  event DefaultTakerFeeUpdate(uint128 defaultTakerFee);

  /// @notice Emitted when limit order fee (maker) is adjusted
  event DefaultMakerFeeUpdate(uint128 defaultMakerFee);

  /// @notice Emitted maintenance margin is updated
  event MMRUpdate(int256 maintenanceMargin);

  /// @notice Emitted initial margin is updated
  event IMRUpdate(int256 initialMargin);

  /// @notice emitted when funding rate operator isupdated
  event OffchainFROperatorUpdate(address provider);

  event BackstopVaultUpdate(address vault);
  event BackstopTriggerMarginFractionUpdate(uint128 fraction);
  event BackstopInheritanceExecuted(
    bytes32 indexed inheritanceId,
    address indexed account,
    address indexed market,
    address inheritingChild,
    uint256 mergePriceE18,
    Types.PositionBalance inheritedPosition,
    Types.PositionBalance childPositionAfter,
    int256 childFreeCollateralDeltaE18
  );
  event BackstopInheritanceFailed(
    address indexed account,
    address indexed market,
    address attemptedChild,
    Types.PositionBalance attemptedPosition,
    bytes reason
  );

  /// @notice emitted when a funding debit exceeds the account's margin plus
  /// its positive unrealized profit (collected by moving oiOpen); amountNotPaid
  /// is the remainder that is forgiven
  event SettlementAmountNotPaidCompletely(
    address account,
    uint128 amountNotPaid
  );

  /// @notice emitted when an account cancels every unused margin/leverage
  /// authorization below `minimumNonce` (audit #42)
  event MarginNoncesInvalidated(address indexed account, uint128 minimumNonce);

  /// @notice One event per landed bankruptcy flag (audit #71).
  /// These events ARE the enumeration surface for the flag set: off-chain
  /// operator tooling reconstructs membership from
  /// flagged/cleared pairs, because the on-chain set is deliberately a bare
  /// mapping with no iteration (see `bankruptFlagged`).
  /// @param account The account verified at strictly negative equity.
  /// @param oraclePrice The single price snapshot the whole batch was
  /// verified against (frozen delist terms after delisting).
  /// @param deficitE18 The equity shortfall, `-equity`, at that snapshot.
  event BankruptAccountFlagged(
    address indexed account,
    uint128 oraclePrice,
    uint256 deficitE18
  );

  /// @notice One event per landed bankruptcy-flag clear (audit #71).
  /// @param account The formerly flagged account verified back at
  /// non-negative equity.
  /// @param oraclePrice The price snapshot the clear was verified against.
  /// @param equityE18 The account's (non-negative) equity at that snapshot.
  event BankruptFlagCleared(
    address indexed account,
    uint128 oraclePrice,
    int256 equityE18
  );

  /// @notice emitted when the owner moves the witnessed-bankruptcy gate
  /// escape hatch (audit #71). `true` disables the 'P87' trade gate.
  event BankruptcyGateDisabledUpdate(bool disabled);

  /// @notice emitted when the owner configures the `flagBankrupt` deficit
  /// dust floor (audit #71).
  event BankruptcyDeficitDustFloorUpdate(uint128 floorE18);

  /// @notice emitted when the owner rotates this market to a new
  /// SignatureVerifier (audit #42 signature-schema cutover)
  event SignatureVerifierUpdate(
    address indexed previousSignatureVerifier,
    address indexed newSignatureVerifier
  );

  /// @notice emitted when global index is updated
  event GlobalIndexUpdate(int256 index, uint128 timestamp);

  /// @notice emitted when a fresh global-index path resets trade batch budget
  event GlobalIndexBatchCountReset(uint128 priorBatchCount, uint128 timestamp);

  /// @notice Emitted by every funding-input transition: replacing the price
  /// oracle, replacing the funder, or stopping trading.
  /// @dev `cutoffTimestamp` is the single instant that divides the two regimes.
  /// Everything up to it is already committed into `cutoffIndexValue`, priced
  /// by the OLD oracle and funder; an emergency stop prices its last interval
  /// with the owner-reviewed inputs in {EmergencyFundingCutoffReviewed}
  /// instead. The next interval starts at the cutoff. The old/new dependency
  /// pairs are emitted unconditionally so a transition can be audited from one
  /// log line — the unchanged side repeats its address.
  event FundingInputTransition(
    FundingInputTransitionKind kind,
    address previousOracle,
    address newOracle,
    address previousFunder,
    address newFunder,
    uint128 cutoffTimestamp,
    int256 cutoffIndexValue
  );

  /// @notice Emitted alongside {FundingInputTransition} when the owner commits
  /// an emergency cutoff by hand, carrying the two inputs a live checkpoint
  /// would have read from the oracle and funder instead.
  /// @dev Companion event rather than extra fields on
  /// {FundingInputTransition}: only this one transition kind has reviewed
  /// inputs, and every other kind would have to pad them with zeroes that read
  /// as real values.
  event EmergencyFundingCutoffReviewed(
    uint128 cutoffTimestamp,
    uint128 cutoffPrice,
    int256 cutoffFundingRate,
    int256 cutoffIndexValue
  );

  //
  // ENUMS
  //
  enum Action {
    TRADE,
    ADD_MARGIN,
    REMOVE_MARGIN,
    ADJUST_LEVERAGE,
    FINAL_WITHDRAWAL,
    BACKSTOP_INHERIT
  }

  /// @dev Which funding input a {FundingInputTransition} changed.
  /// `EMERGENCY_TRADING_STOPPED` is the only kind whose cutoff price and rate
  /// were supplied by the owner rather than read from the live dependencies.
  enum FundingInputTransitionKind {
    ORACLE_REPLACED,
    FUNDER_REPLACED,
    TRADING_STOPPED,
    EMERGENCY_TRADING_STOPPED
  }

  //
  // STRUCTS
  //
  /// @dev Accumulator for per-user batch trade data (used in memory during trade())
  struct TraderAccumulator {
    uint128 totalQuantity;
    uint128 totalFee;
    int256 totalPnl;
    int256 fundsFlow;
    int256 marginDelta;
    uint128 price; // Batch clearing price (same for all trades)
    bool firstFillIsLong; // Direction of this trader's first fill in the batch only
    bool hasActivity; // Whether this trader participated in the batch
  }

  struct BackstopMergeResult {
    Types.PositionBalance childPosition;
    int256 childFreeCollateralDelta;
    bool success;
    // Every non-success return from _mergeInheritedPosition must set this:
    // it is emitted verbatim as the BackstopInheritanceFailed reason, so a
    // forgotten assignment would surface as an empty-reason failure event.
    bytes failureReason;
  }

  /// @dev One registered frozen delist claim (audit #41). Exactly one slot
  /// (16 + 16 bytes), so registering an account costs a single cold write.
  ///
  /// `epoch` doubles as the registration marker and the staleness guard: it is
  /// nonzero only once `_recordDelist` has run, and a claim counts as
  /// registered only while `epoch == delistEpoch`. That is what makes a
  /// registration survive an `abortDelist` harmlessly — see `delistEpoch`.
  struct DelistClaim {
    uint128 epoch;
    uint128 amountE18Raw;
  }

  //**********************************************************//
  //    The below state variables can not change the order    //
  //**********************************************************//

  /// @dev Trder flag 0 for this contract
  bytes32 internal constant TRADER_ID = bytes16(uint128(0));
  bytes32 internal constant NORMAL_TRADER_FLAG = bytes32(uint256(1));
  bytes32 internal constant LIQUIDATION_TRADER_FLAG = bytes32(uint256(2));
  bytes32 internal constant ADL_TRADER_FLAG = bytes32(uint256(3));
  bytes32 internal constant DUAL_LIQUIDATION_TRADER_FLAG = bytes32(uint256(4));

  /// @notice 2-slot packed per-account position + funding state (replaces positionBalances + localIndexes)
  mapping(address => Types.PackedAccountState) internal packedAccounts;

  /// @notice whitelisted account addresses that can perform trade on behalf of taker/maker
  mapping(address => bool) public settlementOperators;

  /// @notice whitelisted trade contract addresses (IsolatedTrader for orders and
  /// book liquidations, IsolatedADL for deleveraging)
  mapping(address => bool) public tradeContracts;

  /// @notice reference to the AccountManager contract that manages sub-account relationships
  IAccountManager public accountManager;

  /// @notice latest system wide index used for funding rate settlements
  Types.Index public globalIndex;

  /// @notice addresses used across the cotnract
  Addresses public addresses;

  /// @notice records the time at which trading becomes active
  uint128 public tradingStartTime;

  /**
   * @notice determines whether the perpetual has been delisted or not
   * No more trades, liquidations, etc. will be supported after
   */
  bool public delisted;

  /// @notice price for delisting. All positions will be closed at this price
  uint128 public delistingPrice;

  /**
   * @notice initial margin requirement, defined as a percentage.
   * Determines the minimum margin needed to open positions and consequently
   * Determines the maximum allowed leverage
   */
  int256 public override initialMarginRequired;

  /**
   * @notice maintenance margin requirement, defined as a percentage.
   * Determines the ratio at which an account is undercollateralized.
   */
  int256 public override maintenanceMarginRequired;

  /// @notice Default taker order fee for this Perpetual
  uint128 public override defaultTakerFee;

  /// @notice Default maker order fee for this Perpetual
  uint128 public override defaultMakerFee;

  /// @notice name of the market DOT/BTC etc..
  string public marketName;

  /// @notice status of the trading as set by the Guardian
  Types.GuardianStatus private tradingStatus;

  /// @notice The account allowed to install funding rates, through either
  /// {setFundingRate} or {setOffChainFundingRate}.
  /// @dev Public since audit #75/#90: this role now gates the rate the exchange
  /// submits, and the upgrade campaign has to be able to verify a market holds
  /// the right one before trusting its funding. Visibility does not move
  /// storage — the slot and its position are unchanged.
  address public offchainFROperator;

  uint256[50] private __gap;

  //**********************************************************//
  //    The above state variables can not change the order    //
  //**********************************************************//

  //◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤ add state variables below ◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤//

  /// @notice keeps track of fee accrued
  uint128 public feePoolAccruedAmt;

  /// @notice Nonces for margin/leverage adjustment signatures (account => nonce => used)
  mapping(address => mapping(uint128 => bool)) public marginNonces;

  /// @notice Vault that authorizes positive-equity liquidation inheritance.
  address public backstopVault;

  /// @notice Fraction of maintenance margin below which positive-equity residuals inherit.
  uint128 public backstopTriggerMarginFractionE18;

  /// @notice Block timestamp when a delist method recorded `delistingPrice`.
  /// Combined with `delistCloseDelaySeconds`, this creates a
  /// settlement-quarantine window after a delist: positions can't be settled
  /// (operator-driven or user-driven) until the delay elapses.
  /// Zero before delisting has occurred.
  uint128 public delistedAt;

  /// @notice Frozen global funding index used for every delist settlement.
  /// Set by the delist method after final funding accrual is applied.
  Types.Index public delistIndex;

  /// @notice Max age of the oracle update. Measured against
  /// `globalIndex.timestamp` when trades, margin operations, and live valuation
  /// reads load the price, and against block time on index updates, batch-budget
  /// resets, oracle replacement, margin removal, and leverage adjustments that
  /// raise leverage or move margin out. Zero disables only this max-age limit,
  /// not the round-integrity checks.
  uint128 public oracleMaxStalenessSeconds;

  /// @notice Max successful trade batches allowed per fresh global-index check.
  /// Zero disables batch-count freshness enforcement.
  uint128 public maxBatchesPerGlobalIndexUpdate;

  /// @notice Successful trade batches since the last fresh global-index check.
  uint128 public batchesSinceGlobalIndexUpdate;

  /// @notice Quarantine window between delisting and position settlement.
  /// Initialized per deployment so testnet can settle quickly while production
  /// has a longer human review window. Read via `CLOSE_DELAY()` for existing
  /// callers.
  uint128 public delistCloseDelaySeconds;

  /// @notice Pinned market-regime flag for binary futures.
  bool public isBinaryFutureMarketFlag;

  /// @dev False only for upgraded markets until the one-time migration runs.
  bool private binaryFlagInitialized;

  /// @notice Block of the last `setOracle` that actually changed the feed.
  /// @dev Mirrors the price oracles' `lastUpdateBlock`: the per-update
  /// movement cap only bounds the price if updates cannot be chained inside
  /// one block. Without this, four in-cap swaps in a single transaction move
  /// the mark by four times the cap with no block in between. Zero on markets
  /// that predate this field, which reads as "no replacement yet" and is
  /// correct.
  uint256 public lastOracleReplacementBlock;

  /// @notice Lowest margin/leverage authorization nonce an account still
  /// honours. Advancing it with `invalidateMarginNoncesUpTo` cancels every
  /// unused signature below the new minimum in one transaction (audit #42).
  /// Zero (the default for every existing account) accepts all nonces, so the
  /// upgrade is inert until an account opts in.
  mapping(address => uint128) public minimumMarginNonce;

  /// @notice Contract-witnessed bankrupt accounts (audit #71).
  /// True while `flagBankrupt` verified the account at strictly negative
  /// equity and no `clearBankruptFlag` has verified it recovered.
  ///
  /// Deliberately a bare mapping plus `bankruptFlaggedCount` — NO array, NO
  /// capacity, NO enumerable structure of any kind. Nothing on-chain ever
  /// iterates the set: the trade gate reads only the count, and flag/clear
  /// verify NAMED accounts, so every operation is O(1) and membership is
  /// unbounded by construction. A capped structure had a real hole: witnesses
  /// beyond the cap are dropped, and when the capped subset drains the gate
  /// reopens while known-but-skipped bankruptcies still stand — a
  /// front-runnable window. Unbounded membership makes that impossible: the
  /// gate opens only when the LAST witnessed bankruptcy clears. Off-chain
  /// enumeration comes from the
  /// `BankruptAccountFlagged` / `BankruptFlagCleared` events, never from
  /// chain iteration. Storage growth is bounded by real
  /// simultaneous bankruptcies; cleared entries zero their slots.
  mapping(address => bool) public bankruptFlagged;

  /// @notice Number of currently flagged bankrupt accounts. `trade()` reverts
  /// pure-normal batches with 'P87' while this is nonzero, unless the
  /// `bankruptcyGateDisabled` escape hatch is set. Liquidation-only,
  /// dual-liquidation-only, and ADL-only batches always pass.
  uint128 public bankruptFlaggedCount;

  /// @notice Minimum equity deficit (e18 raw USDM) `flagBankrupt` accepts.
  /// ZERO IS A SENTINEL meaning "use the compiled default"
  /// (`DEFAULT_BANKRUPTCY_DEFICIT_DUST_FLOOR_E18`, read through
  /// `effectiveBankruptcyDeficitDustFloorE18()`), so upgraded proxies whose
  /// new slots zero-initialize get a NONZERO floor with no operator ceremony
  /// and no reinitializer. `setBankruptcyDeficitDustFloor` rejects zero, so a
  /// stored zero only ever means "never configured".
  uint128 public bankruptcyDeficitDustFloorE18;

  /// @notice Escape hatch for the witnessed-bankruptcy trade gate. INVERTED
  /// (a disabled-flag) so the zero-initialized default on upgraded proxies is
  /// gate-ACTIVE with no operator ceremony. See `setBankruptcyGateDisabled`
  /// for the operator doctrine.
  bool public bankruptcyGateDisabled;

  /// @notice Registered frozen delist claims (audit #41). One slot per
  /// account. A stored `epoch` equal to `delistEpoch` marks the account
  /// registered, which distinguishes "registered at zero" (a negative-equity
  /// account, which registers so count parity against the off-chain
  /// enumeration holds) from "never registered".
  ///
  /// `amountE18Raw` is the account's GROSS claim at the frozen delisting
  /// terms, computed from contract storage alone by
  /// `_delistClaimStanding`. It is a snapshot only in the bookkeeping
  /// sense: after `delisted` flips, `trade()` ('P1'), `addMargin`,
  /// `removeMargin`, `removeMarginUpTo`, and `adjustLeverage` are all
  /// `notDelisted`, so no path can move an account's margin or position
  /// between registration and settlement. The value cannot go stale.
  mapping(address => DelistClaim) public delistClaims;

  /// @notice Number of accounts registered this epoch, by `registerDelistClaims`
  /// or by a settlement call's pre-lock registration. The operator's
  /// count-parity check against the enumeration artifact's claimant count.
  uint128 public registeredDelistClaimCount;

  /// @notice Locked pro-rata payout ratio (e18). Zero until
  /// `delistClaimRatioLocked`; `1e18` means every registered claim pays in
  /// full and the mechanism is a no-op.
  uint128 public delistClaimRatioE18;

  /// @notice Sum of every registered claim. uint256 because the sum of
  /// per-account uint128 claims has no uint128 bound. Frozen in meaning once
  /// the ratio locks: it is that ratio's denominator forever.
  uint256 public registeredDelistClaimTotalE18Raw;

  /// @notice Registered claim value not yet settled. Decremented by each
  /// settlement. Zero is the on-chain half of "settlement is complete" that
  /// gates the residual sweep. Accounts registered at zero never contribute,
  /// so they cannot block it.
  uint256 public outstandingDelistClaimE18Raw;

  /// @notice Incremented by every `_recordDelist`, which also zeroes the
  /// counters above. This is how a registration is scoped to the delisting it
  /// was computed for.
  ///
  /// `abortDelist` can unwind a delisting after claims were already
  /// registered, and a later re-delist may freeze a DIFFERENT price. Per-account
  /// mapping entries cannot be cleared (storage is not enumerable), so instead
  /// they are versioned: entries from the aborted delisting keep the old epoch,
  /// never match the new one, and are inert. Without this, a re-delisted market
  /// would pay claims valued at the abandoned settlement price.
  ///
  /// ZERO IS A RESERVED, NEVER-VALID EPOCH, and that reservation is load
  /// bearing. A market that was ALREADY DELISTED when this implementation was
  /// upgraded in wakes with `delistEpoch == 0` (new slots zero-initialize)
  /// while `delisted` is still true. An unwritten claim slot also reads epoch
  /// 0, so without the reservation every account on that market would match
  /// an empty entry, look "registered for zero", and settle for NOTHING —
  /// a total loss of frozen equity — while registration silently skipped
  /// every account as already done. Epoch 0 therefore means "this delisting
  /// predates the mechanism": `_delistClaimsActive()` is false, the legacy
  /// close path runs untouched, and registration reverts loudly with 'P92'
  /// instead of appearing to succeed. Every epoch opened after the upgrade is
  /// >= 1 because `_resetDelistClaimState` pre-increments.
  uint128 public delistEpoch;

  /// @notice True once `_lockDelistClaimRatioIfNeeded` has actually locked the
  /// ratio. Closes registration and pins the payout ratio permanently — there
  /// is deliberately no top-up-and-recompute path, because a ratio that can
  /// move after the first payout reintroduces exactly the order dependence
  /// this fixes. The funding window is the grace period, before the lock.
  bool public delistClaimRatioLocked;

  /// @notice One-way eligibility for the full-collateral binary bound case.
  /// A move into leverage revokes it permanently; raising IMR cannot restore it.
  bool public binaryFullCollateralBoundsEligible;

  /// @notice True after deployment or the reviewed one-time fleet migration.
  bool public binaryFullCollateralBoundsEligibilityInitialized;

  /// @notice Timestamp when the owner finalized the complete claimant
  /// population for the current delist epoch. Zero means registration remains
  /// open unless a permissionless fallback settlement has already locked the
  /// payout ratio.
  /// Appended after every previously deployed storage field.
  uint128 public delistClaimsFinalizedAt;

  /// @notice True once a real position starts settling through the
  /// unfinalized permissionless fallback. A late owner finalization remains
  /// possible while the ratio is unlocked, but receives no funding grace.
  /// Packed beside `delistClaimsFinalizedAt`.
  bool public delistFallbackSettlementStarted;

  //◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣ add state variables above ◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣//

  uint8 private constant ORACLE_PRICE_DECIMALS = 18;
  uint256 private constant ADL_BASE = 1e18;
  uint256 private constant ADL_BPS_DENOMINATOR = 10000;
  uint256 private constant ADL_REPLACEMENT_CAPACITY_SCALE = 1e54;
  uint256 private constant BINARY_BOUND_ROUNDING_SLACK = 5e14;

  /// @dev Default `flagBankrupt` deficit dust floor: 0.01 USDM (e18 raw).
  /// Applied whenever `bankruptcyDeficitDustFloorE18` is zero (the sentinel),
  /// which is exactly the state every upgraded proxy wakes up in — so the
  /// gate arms with a meaningful floor fleet-wide without a per-market
  /// configuration campaign. Large enough to reject rounding-scale deficits
  /// (funding settlement and PnL math round at wei scale), small enough that
  /// any economically real bankruptcy still flags. Deficits below the floor
  /// are deliberately not flaggable.
  uint128 internal constant DEFAULT_BANKRUPTCY_DEFICIT_DUST_FLOOR_E18 = 1e16;

  /// @dev Calldata bound for one `flagBankrupt` / `clearBankruptFlag` batch.
  /// Purely a griefing/DoS bound on per-call work; callers needing more
  /// submit more batches.
  uint256 internal constant MAX_BANKRUPTCY_FLAG_BATCH = 64;

  /// @dev Funding grace measured from owner finalization (audit #41): when the
  /// owner finalizes before the original close-delay boundary, claims open at
  /// the later of that boundary and `delistClaimsFinalizedAt + 12 hours`, and
  /// abort stays possible until then. Twelve hours: long enough for the
  /// operator to run the enumeration tool, read `delistClaimShortfallE18Raw()`,
  /// move funds, and re-verify; short enough that the extra user lockout stays
  /// bounded and humane. Deliberately a COMPILED CONSTANT, not storage:
  ///
  ///  - The close delay it extends has no owner setter — it is fixed at
  ///    `initialize()` and back-filled once by `initializeDelistCloseDelay`.
  ///    There is no owner-configurable precedent here to mirror, so adding
  ///    one would be inventing a new config style.
  ///  - A constant bounds the opt-in grace by construction. If the owner never
  ///    finalizes, claims still open at the original close-delay boundary; if
  ///    it does finalize in time, it cannot choose a longer funding lockout.
  ///  - It costs no storage slot and needs no per-market rollout ceremony
  ///    across the live market fleet.
  ///
  /// The grace is charged only when the owner finalizes the verified claimant
  /// population before the original boundary. Late finalization may still seal
  /// an untouched population, but it cannot move an already-open permissionless
  /// settlement boundary back into the future.
  uint128 internal constant DELIST_CLAIM_FUNDING_GRACE_SECONDS = 12 hours;

  /// @dev Calldata bound for one `registerDelistClaims` / `settleDelistClaims`
  /// batch. Purely a per-call work bound; callers needing more submit more
  /// batches, which is safe because both are idempotent.
  uint256 internal constant MAX_DELIST_CLAIM_BATCH = 64;

  /**
   * @dev Modifier to ensure the function is not run after perpetual is delisted
   */
  modifier notDelisted() {
    require(!delisted, 'P1');
    _;
  }

  /**
   * @dev Modifier to ensure the function is only run after perpetual is delisted
   */
  modifier afterDelisting() {
    require(delisted, 'P2');
    _;
  }

  /**
   * @dev Modifier requiring the settlement-quarantine window to have
   * elapsed. Used by `closePosition()`, `closePositionForAccounts()`, and
   * `settleDelistClaims()` so no settlement path can race ahead of an
   * `abortDelist()` reaction window. Reverts with 'P40' if the window has
   * not yet elapsed.
   *
   * Owner finalization can move the boundary returned by
   * `delistClaimsOpenAt()` to preserve a complete funding grace. Without that
   * optional finalization, the original close-delay boundary remains the
   * permissionless liveness fallback.
   *
   * `block.timestamp` (via `_blockTimestamp()`) is sound here and in every
   * audit #41 path: all of them require `delisted == true`, while `trade()`
   * is `notDelisted` and reverts with 'P1' once that flag is set. The two
   * are mutually exclusive, so none of this logic is reachable from the
   * volatile-context trade path where the MegaETH compute-allowance rule
   * forbids block metadata.
   */
  modifier afterDelistDelay() {
    require(delisted, 'P2');
    _requireDelistCloseDelayConfigured();
    require(_blockTimestamp() >= delistClaimsOpenAt(), 'P40');
    _;
  }

  /**
   * Throws if called by any account other than the guardian contract
   */
  modifier onlyGuardianContract() {
    require(addresses.guardian == _msgSender(), 'P3');
    _;
  }

  /**
   * Throws if called by any account other than the white listed account.
   */
  modifier onlyoffchainFROperator() {
    /// @dev applied to a gas less method so using msgSender() instead of _msgSender
    require(offchainFROperator == msgSender(), 'P4');
    _;
  }

  modifier onlyValidCaller(address account) {
    /**
     * @dev using msgSender() instead of _msgSender(), as the methods
     * using onlyValidCaller modifier are gasless, can be invoked by
     * a trusted relayer
     *
     * Market-scoped since audit #38. Reduce-only passes deliberately: the only
     * caller-checked entrypoint is closePosition, which is a wind-down's exit.
     */
    require(
      _accountMarketPermission(account, msgSender()) !=
        Types.MarketPermission.NONE,
      'P5'
    );
    _;
  }

  modifier onlySettlementOperator() {
    require(settlementOperators[_msgSender()], 'P10');
    _;
  }

  /**
   * @dev Reverts 'P7' while the guardian has trading halted for this
   * market. Applied to trade() and to every other entrypoint that realizes
   * the global funding index into per-account state (margin operations,
   * permissionless settlement): during a halt — e.g. while remediating a
   * bad funding-rate submission — neither users nor keepers may bake the
   * halted index into accounts ahead of operator action.
   */
  modifier whenTradingAllowed() {
    require(
      IGuardian(addresses.guardian).isTradingAllowed(address(this)),
      'P7'
    );
    _;
  }

  /**
   * @dev Reverts 'P7' while trading is halted, EXCEPT for the guardian
   * contract itself. Applied to the entrypoints that advance `globalIndex`
   * without touching any per-account state — the permissionless
   * {updateGlobalIndex} and the operator-only {setFundingRate} and
   * {setOffChainFundingRate}. `whenTradingAllowed` already
   * stops a halted index from being realized INTO an account; this stops the
   * index itself from moving (audit #86).
   *
   * Why the index must freeze, not just its per-account realization: the
   * owner's re-pricing tool for a suspect interval is
   * {emergencyStopTradingAtCutoff}, and its cutoff cannot predate the last
   * committed index ('P86'). Every advance during a halt therefore ratchets
   * that floor forward and permanently removes the repriced span from the
   * owner's reach. Freezing `globalIndex.timestamp` for the duration of the
   * halt is what preserves the cutoff's reach.
   *
   * The two tools are for different problems and both remain available:
   *   - The rate is TRUSTED and the halt is about something else (a feed
   *     swap, a mode change): the guardian's own checkpoint below commits the
   *     elapsed interval at the STORED rate, which is correct by assumption.
   *   - The rate itself is SUSPECT: the owner commits a reviewed cutoff
   *     through {emergencyStopTradingAtCutoff}, which computes its index
   *     directly and never routes through these entrypoints.
   *
   * Funding is not LOST during an unrelated halt. Accrual is lazy — the
   * index only moves when someone advances it — so the first advance after
   * the halt lifts prices the whole elapsed span at the stored rate and at
   * the oracle price that advance reads. That matches the no-halt outcome
   * only if neither would have changed during the halt. If instead the span
   * must be repriced, the reviewed cutoff runs first and sets the new
   * starting point.
   *
   * The exemption exists because `Guardian.setFundingRateStatus` calls
   * {updateGlobalIndex} on this market to settle the elapsed interval before
   * flipping funding status, and flipping funding during a trading halt is a
   * primary remediation move. Without the exemption the enable direction
   * would revert outright and the disable direction would lose its
   * checkpoint to Guardian's swallowing low-level call (logged only as
   * `FundingStatusSettlementSkipped`). That swallow is preserved
   * deliberately: a dead feed must never be able to brick a halt.
   *
   * Uses raw `msg.sender`, not the relay-aware `msgSender()`. The Guardian
   * calls this market directly and never through the trusted forwarder, and
   * Perpetual's relay/non-relay sender split is deliberate — routing an
   * authorization check through relay logic would let a forwarder-supplied
   * suffix claim to be the guardian. `onlyGuardianContract` compares the same
   * way: Perpetual's `_msgSender()` is OpenZeppelin Context's and returns
   * `msg.sender`.
   *
   * Reads `tradingStatus` locally rather than through
   * `IGuardian.isTradingAllowed`, matching the oracle-replacement continuity
   * check. `Guardian.isTradingAllowed(perp)` is a pass-through to this exact
   * storage slot, so the two agree on an honest guardian — but the exemption
   * already trusts `addresses.guardian` for the CALLER half of this gate, and
   * sourcing the STATUS half from the same address would let a replaced
   * guardian claim trading is allowed and hand the permissionless surface
   * back to everyone. The local read confines the guardian's power here to
   * its own call path. It also means a broken guardian cannot brick index
   * advancement on a market that is running normally.
   */
  modifier whenIndexAdvancementAllowed() {
    require(
      tradingStatus == Types.GuardianStatus.ALLOWED ||
        msg.sender == addresses.guardian,
      'P7'
    );
    _;
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(address _oracleFactory) {
    require(
      _oracleFactory != address(0) && _oracleFactory.code.length > 0,
      'P93'
    );
    ORACLE_FACTORY = IOracleFactory(_oracleFactory);
    _disableInitializers();
  }

  /**
   * @param  _marketName          The name of the perpetual market dot/movr/btc/eth etc..
   * @param  _addresses           The address of contracts/pool to be stored in perpetual
   * @param  _trustedForwarder    The ERC-2771 forwarder contract whose appended sender
   *                              `msgSender()` trusts; it must have deployed code
   * @param  _accountManager      The address of the AccountManager contract
   * @param  _initialMargin       The initial margin to use for opening positions.
   * @param  _maintenanceMargin   The maintenance margin ratio (e18); below it an account is
   *                              liquidatable. Must be > 0 and <= _initialMargin.
   * @param  _defaultMakerFee     The default fee to be paid on trade by maker
   * @param  _defaultTakerFee     The default fee to be paid on trade by taker
   * @param  _delistCloseDelaySeconds  Delay between delist and settlement.
   * @param  _binaryFutureMarket True when this market should use binary-future margin rules.
   */
  function initialize(
    string memory _marketName,
    Addresses memory _addresses,
    address _trustedForwarder,
    address _accountManager,
    int256 _initialMargin,
    int256 _maintenanceMargin,
    uint128 _defaultMakerFee,
    uint128 _defaultTakerFee,
    uint128 _delistCloseDelaySeconds,
    bool _binaryFutureMarket
  ) public initializer {
    require(_addresses.marginMath != address(0), 'P6');
    require(_accountManager != address(0), 'P20');
    _requireFactoryOracle(_addresses.oracle);

    marketName = _marketName;
    _setDelistCloseDelaySeconds(_delistCloseDelaySeconds);
    isBinaryFutureMarketFlag = _binaryFutureMarket;
    binaryFlagInitialized = true;
    binaryFullCollateralBoundsEligibilityInitialized = true;
    binaryFullCollateralBoundsEligible =
      _binaryFutureMarket &&
      _initialMargin == int256(ADL_BASE);
    if (_binaryFutureMarket) {
      _requireBinaryEvaluatorLocked(_addresses.evaluator);
      _requireBinaryFunderLocked(_addresses.funder);
    }

    addresses = _addresses;
    _requireValidOracle(_addresses.oracle);
    accountManager = IAccountManager(_accountManager);

    offchainFROperator = _msgSender();

    globalIndex.timestamp = _blockTimestamp();

    __MetaTransaction_init(_trustedForwarder);
    __Ownable_init(_msgSender());
    __Ownable2Step_init();

    uint256 imrRaw = _validateInitialMargin(_initialMargin);
    require(_maintenanceMargin > 0, 'P27');
    require(_maintenanceMargin <= _initialMargin, 'P28');
    _requireAdlReplacementCapacityInvariant(
      _addresses.oracle,
      _addresses.evaluator,
      imrRaw,
      uint256(_maintenanceMargin),
      _defaultMakerFee,
      _defaultTakerFee
    );
    setFeePool(_addresses.feePool);
    setDefaultMakerFee(_defaultMakerFee);
    setDefaultTakerFee(_defaultTakerFee);
    _setInitialMargin(_initialMargin);
    setMaintenanceMargin(_maintenanceMargin);

    emit OffchainFROperatorUpdate(offchainFROperator);
  }

  /**
   * @notice One-time initializer for upgraded proxy markets that predate
   * `delistCloseDelaySeconds`.
   * @dev New deployments set this during `initialize()` and therefore cannot
   * call this migration initializer later.
   * @param _delistCloseDelaySeconds Delay between delist and settlement.
   */
  function initializeDelistCloseDelay(
    uint128 _delistCloseDelaySeconds
  ) external onlyOwner reinitializer(2) {
    require(delistCloseDelaySeconds == 0, 'P62');
    _setDelistCloseDelaySeconds(_delistCloseDelaySeconds);
  }

  /**
   * @notice One-time initializer for upgraded proxy markets that predate the
   * pinned binary-future market flag.
   * @dev Snapshots the old live-config fingerprint exactly once. New
   * deployments set this during `initialize()` and therefore cannot call this
   * migration initializer later.
   */
  function initializeBinaryFutureMarketFlag()
    external
    onlyOwner
    reinitializer(3)
  {
    require(!binaryFlagInitialized, 'P63');
    require(delistCloseDelaySeconds > 0, 'P66');
    bool inferredBinaryFutureMarket = _inferBinaryFromLiveConfig();
    if (inferredBinaryFutureMarket) {
      _requireBinaryEvaluatorLocked(addresses.evaluator);
      _requireBinaryFunderLocked(addresses.funder);
    }
    isBinaryFutureMarketFlag = inferredBinaryFutureMarket;
    binaryFlagInitialized = true;
    emit BinaryFutureMarketFlagInitialized(isBinaryFutureMarketFlag);
  }

  /**
   * @notice One-time migration for binary proxies deployed before the
   * full-collateral eligibility bit existed.
   * @dev The caller supplies the reviewed expectation so a live leveraged
   * market cannot be silently reclassified by first raising its IMR to one.
   * The cutover tooling checks the exact fleet config before invoking this.
   */
  function initializeBinaryFullCollateralBoundsEligibility(
    bool expectedEligible
  ) external onlyOwner reinitializer(4) {
    require(binaryFlagInitialized && isBinaryFutureMarketFlag, 'P96');
    require(!binaryFullCollateralBoundsEligibilityInitialized, 'P97');
    require(tradingStatus != Types.GuardianStatus.ALLOWED, 'P7');
    bool eligible = initialMarginRequired == int256(ADL_BASE);
    require(eligible == expectedEligible, 'P98');
    binaryFullCollateralBoundsEligible = eligible;
    binaryFullCollateralBoundsEligibilityInitialized = true;
    emit BinaryFullCollateralBoundsEligibilityInitialized(eligible);
  }

  /**
   * @notice Performs one or multiple matches between two or more trading parties
   * @param  _accounts  A sorted, unique account table referenced by trade indices
   * @param  _trades    Trades to execute in this batch
   */
  function trade(
    address[] memory _accounts,
    TradeArg[] memory _trades
  ) public override notDelisted nonReentrant whenTradingAllowed {
    _verifyAccounts(_accounts);

    require(_trades.length > 0, 'P38');
    _requireGlobalIndexBatchBudget();

    Types.Context memory context = _loadContext(false);

    // all trades will have the same trader: IsolatedTrader (orders, including
    // book liquidations) or IsolatedADL
    address trader = _trades[0].trader;

    // Trader must be whitlisted in tradeContracts
    require(tradeContracts[trader], 'P9');

    bytes32 traderFlags = ITrader(trader).getTraderFlag();

    /// @dev not gasless: the settlement operator calls directly and pays gas,
    /// so the raw `_msgSender()` is used
    address sender = _msgSender();

    // settle accounts for any pending funding payments
    Types.PositionBalance[] memory initialPositionBalances = _applyFundingRate(
      context,
      _accounts
    );
    Types.PositionBalance[]
      memory runningPositionBalances = new Types.PositionBalance[](
        _accounts.length
      );
    bool[] memory onlySameSideReductions = new bool[](_accounts.length);
    for (uint128 i = 0; i < _accounts.length; i++) {
      runningPositionBalances[i] = _copyPositionBalance(
        initialPositionBalances[i]
      );
      onlySameSideReductions[i] = initialPositionBalances[i].qPos > 0;
    }

    // if a normal trade is requested
    if (traderFlags == NORMAL_TRADER_FLAG) {
      require(settlementOperators[sender] == true, 'P10');
    }
    // ADL is protocol settlement, so the same relayer whitelist controls it.
    else if (traderFlags == ADL_TRADER_FLAG) {
      require(settlementOperators[sender] == true, 'P11');
    } else {
      revert('P12');
    }

    // Use the already-loaded global index timestamp to avoid a block.timestamp
    // read in the trade hot path. MegaETH applies a lower compute ceiling to
    // transactions that touch volatile block data.
    uint128 settlementTimestamp = context.index.timestamp;
    require(
      tradingStartTime > 0 && settlementTimestamp > tradingStartTime,
      'P8'
    );

    // For regular batches (flag 1), including book-liquidation fills (per-fill
    // flags 2 and 4), accumulate per-user data and emit aggregated events.
    // For ADL batches (flag 3), emit per-trade TradeExecuted events.
    bool isRegularTrade = traderFlags == NORMAL_TRADER_FLAG;
    // First regular fill's price, then the price every later regular fill in
    // this batch must match ('P39' — the uniform clearing price invariant).
    bool hasClearingPrice = false;
    // True once any fill's PER-FILL flags came back pure normal (neither side
    // forced). Known only after each fill executes, so it accumulates across
    // the loop and the witnessed-bankruptcy gate tests it after the loop.
    bool hasPureNormalFill = false;
    uint128 clearingPrice = 0;
    bool[] memory liquidationMarginBypass = new bool[](_accounts.length);

    // Create per-account accumulators for batch event aggregation (regular trades only)
    TraderAccumulator[] memory accumulators = new TraderAccumulator[](
      _accounts.length
    );

    for (uint128 i = 0; i < _trades.length; i++) {
      require(
        _trades[i].makerIndex < _accounts.length &&
          _trades[i].takerIndex < _accounts.length,
        'P50'
      );
      require(_trades[i].trader == trader, 'P51');

      address maker = _accounts[_trades[i].makerIndex];
      address taker = _accounts[_trades[i].takerIndex];

      // Self-trade prevention; position updates aren't needed
      if (maker == taker) {
        continue;
      }

      Types.TradeResult memory tradeResult = ITrader(trader).trade(
        maker,
        taker,
        context.price,
        _trades[i].data,
        settlementTimestamp
      );

      bool isBookLiquidationTaker = isRegularTrade &&
        tradeResult.traderFlags == LIQUIDATION_TRADER_FLAG;
      bool isDualBookLiquidation = isRegularTrade &&
        tradeResult.traderFlags == DUAL_LIQUIDATION_TRADER_FLAG;
      // Witnessed-bankruptcy gate input (audit #71): a fill is "pure normal"
      // only when the per-fill flags say neither side was forced. Book
      // liquidation has no trader contract of its own — it arrives INSIDE
      // normal-flag batches and is identified per fill right here — so the
      // gate below cannot key on the batch-level `traderFlags`; doing so
      // would block forced exits, the main way a flagged account returns to
      // non-negative equity so `clearBankruptFlag` can lift the gate.
      hasPureNormalFill =
        hasPureNormalFill ||
        (isRegularTrade && tradeResult.traderFlags == NORMAL_TRADER_FLAG);

      if (isBookLiquidationTaker || isDualBookLiquidation) {
        // Book-side forced liquidation orders are protocol-generated,
        // unsigned, reduce-only market orders. A normal counterparty keeps
        // ordinary account-health checks; when both sides are forced, both
        // distressed accounts receive the liquidation end-state allowance.
        liquidationMarginBypass[_trades[i].takerIndex] = true;
      }
      if (isDualBookLiquidation) {
        liquidationMarginBypass[_trades[i].makerIndex] = true;
      }

      if (isRegularTrade) {
        if (!hasClearingPrice) {
          hasClearingPrice = true;
          clearingPrice = tradeResult.price;
        } else {
          require(tradeResult.price == clearingPrice, 'P39');
        }
      }

      feePoolAccruedAmt += tradeResult.makerFee + tradeResult.takerFee;

      /**
       * @dev Transfer margin from bank to perpetual or perpetual to margin bank
       * depending on flow of funds. Note collateral are never moved to perpetual contract,
       * margin bank holds them
       */

      // perform all positive margin transfers before negative to ensure solvency
      if (tradeResult.makerFundsFlow >= 0) {
        _transferMargin(maker, tradeResult.makerFundsFlow);
      }
      if (tradeResult.takerFundsFlow >= 0) {
        _transferMargin(taker, tradeResult.takerFundsFlow);
      }
      if (tradeResult.makerFundsFlow < 0) {
        _transferMargin(maker, tradeResult.makerFundsFlow);
      }
      if (tradeResult.takerFundsFlow < 0) {
        _transferMargin(taker, tradeResult.takerFundsFlow);
      }

      // update position balance (packed storage)
      packedAccounts[maker].store(
        tradeResult.makerBalance,
        context.index.value
      );
      packedAccounts[taker].store(
        tradeResult.takerBalance,
        context.index.value
      );

      Types.PositionBalance memory makerPrevPosition = runningPositionBalances[
        _trades[i].makerIndex
      ];
      Types.PositionBalance memory takerPrevPosition = runningPositionBalances[
        _trades[i].takerIndex
      ];
      onlySameSideReductions[_trades[i].makerIndex] =
        onlySameSideReductions[_trades[i].makerIndex] &&
        _isSameSideReduction(makerPrevPosition, tradeResult.makerBalance);
      onlySameSideReductions[_trades[i].takerIndex] =
        onlySameSideReductions[_trades[i].takerIndex] &&
        _isSameSideReduction(takerPrevPosition, tradeResult.takerBalance);

      // Precompute margin deltas to reduce stack depth
      int256 makerMarginDelta = int256(
        uint256(tradeResult.makerBalance.margin)
      ) - int256(uint256(makerPrevPosition.margin));
      int256 takerMarginDelta = int256(
        uint256(tradeResult.takerBalance.margin)
      ) - int256(uint256(takerPrevPosition.margin));
      uint128 tradeTimestamp = settlementTimestamp;

      emit AccountPositionUpdate(
        maker,
        sender,
        tradeResult.makerBalance,
        makerPrevPosition,
        Action.TRADE,
        globalIndex.value,
        tradeTimestamp,
        makerMarginDelta
      );

      emit AccountPositionUpdate(
        taker,
        sender,
        tradeResult.takerBalance,
        takerPrevPosition,
        Action.TRADE,
        globalIndex.value,
        tradeTimestamp,
        takerMarginDelta
      );

      if (isDualBookLiquidation) {
        emit ForcedBookLiquidationFill(
          maker,
          tradeResult.makerHash,
          tradeResult.makerFundsFlow
        );
      }
      if (isBookLiquidationTaker || isDualBookLiquidation) {
        emit ForcedBookLiquidationFill(
          taker,
          tradeResult.takerHash,
          tradeResult.takerFundsFlow
        );
      }

      if (isRegularTrade) {
        // Accumulate per-user trade data for BatchTradeExecuted events
        _accumulateTradeResult(
          accumulators,
          _trades[i].makerIndex,
          tradeResult.tradeQuantity,
          tradeResult.makerFee,
          tradeResult.makerPnl,
          tradeResult.makerFundsFlow,
          makerMarginDelta,
          tradeResult.price,
          !tradeResult.isBuy // maker is opposite side of taker
        );
        _accumulateTradeResult(
          accumulators,
          _trades[i].takerIndex,
          tradeResult.tradeQuantity,
          tradeResult.takerFee,
          tradeResult.takerPnl,
          tradeResult.takerFundsFlow,
          takerMarginDelta,
          tradeResult.price,
          tradeResult.isBuy
        );
      } else {
        // Only ADL batches reach here; emit per-trade TradeExecuted events
        emit TradeExecuted(
          maker,
          taker,
          tradeResult.makerHash,
          tradeResult.takerHash,
          tradeResult.makerFee,
          tradeResult.takerFee,
          tradeResult.makerPnl,
          tradeResult.takerPnl,
          tradeResult.makerFundsFlow,
          tradeResult.takerFundsFlow,
          makerMarginDelta,
          takerMarginDelta,
          tradeResult.tradeQuantity,
          tradeResult.price,
          tradeResult.isBuy
        );
      }

      runningPositionBalances[_trades[i].makerIndex] = _copyPositionBalance(
        tradeResult.makerBalance
      );
      runningPositionBalances[_trades[i].takerIndex] = _copyPositionBalance(
        tradeResult.takerBalance
      );
    }

    // Witnessed-bankruptcy trade gate (audit #71): while any
    // contract-verified bankrupt account is standing, new risk accrues
    // claims against a payer who cannot pay, so batches carrying a pure
    // normal fill revert until `clearBankruptFlag` has cleared every witnessed
    // bankruptcy (possible once it is liquidated, deleveraged, topped up, or
    // recovers). Ordered short-circuit-first so a batch with no pure-normal
    // fill — liquidation-only, dual-liquidation-only, or ADL-only — never
    // reads the count slot and always passes: forced exits are what let the
    // flags be cleared. `_loadContext`, margin operations, and every
    // forced-exit path never see this check. Placed before the inheritance
    // block so a doomed batch does no inheritance work. The off-chain engine
    // is the primary defense (it refuses to submit pure-normal fills while
    // the flag count is nonzero); this revert is the backstop for a
    // compromised or buggy submitter.
    require(
      !hasPureNormalFill || bankruptFlaggedCount == 0 || bankruptcyGateDisabled,
      'P87'
    );

    // Every account is verified in its post-fill state, before backstop
    // inheritance merges any liquidation residual.
    // A liquidation child that also trades in the batch is judged on its own
    // fills, which is what the off-chain engine plans, and a residual it inherits
    // cannot revert the batch in its name. The liquidatee's forced reduction
    // passes under its liquidation allowance, and a batch that fails makes no
    // vault calls.
    // @dev ADL fills return empty maker and taker hashes; book-liquidation
    // fills carry the forced orders' EIP-712 hashes
    _verifyAccountState(
      context,
      _accounts,
      initialPositionBalances,
      traderFlags,
      liquidationMarginBypass,
      onlySameSideReductions
    );

    if (isRegularTrade) {
      for (uint128 i = 0; i < _accounts.length; i++) {
        if (liquidationMarginBypass[i]) {
          _attemptBackstopInheritance(_accounts[i]);
        }
      }
    }

    // Emit BatchTradeExecuted events for each user with activity (regular trades only)
    if (isRegularTrade) {
      for (uint128 i = 0; i < _accounts.length; i++) {
        if (accumulators[i].hasActivity) {
          emit BatchTradeExecuted(
            _accounts[i],
            accumulators[i].totalQuantity,
            accumulators[i].totalFee,
            accumulators[i].totalPnl,
            accumulators[i].fundsFlow,
            accumulators[i].marginDelta,
            accumulators[i].price,
            accumulators[i].firstFillIsLong
          );
        }
      }
    }

    _consumeGlobalIndexBatchBudget();
  }

  /**
   * @notice Allows caller to add margin to an account's position
   * @param _account address of the account to add margin to
   * @param _amount amount of margin to be added
   * @param _nonce unique nonce to prevent replay attacks
   * @param _deadline last block timestamp at which the authorization is valid
   * @param _signature EIP-712 signature from a signer authorized for the account
   *  in this market
   * @dev Signature verification accepts the account owner, a sub-account the owner
   *      approved, or a system-account operator with permission in this market;
   *      a reduce-only operator may add margin.
   *      Settlement operator submits the transaction, but funds move based on user's signature.
   */
  function addMargin(
    address _account,
    uint128 _amount,
    uint128 _nonce,
    uint64 _deadline,
    TypedSignature.Signature calldata _signature
  ) public onlySettlementOperator notDelisted nonReentrant whenTradingAllowed {
    require(_amount > 0, 'P13');
    {
      (Types.PositionBalance memory checkBal, ) = packedAccounts[_account]
        .load();
      require(checkBal.qPos > 0, 'P14');
    }
    address signer = ISignatureVerifier(addresses.signatureVerifier)
      .recoverMarginSigner(
        address(this),
        _account,
        _amount,
        true,
        _nonce,
        _deadline,
        _signature
      );
    _consumeMarginAuthorization(_account, signer, _nonce, _deadline);

    Types.Context memory context = _loadContext(false);

    // transfer margin to perpetual address
    IMarginBank(addresses.marginBank).transferMarginToAccount(
      _account,
      address(this),
      _amount
    );

    // load, update margin, store
    (Types.PositionBalance memory balance, int256 fi) = packedAccounts[_account]
      .load();
    Types.PositionBalance memory prevPosition = _copyPositionBalance(balance);
    balance.margin += _amount;
    packedAccounts[_account].store(balance, fi);

    // apply funding rate. The deposit was credited above, so it can cover a
    // pending debit the prior margin alone could not.
    _applyFundRateToAccount(context, _account);

    (Types.PositionBalance memory updatedBal, ) = packedAccounts[_account]
      .load();
    // marginDelta reports the bank -> position transfer (exactly the
    // deposit): off-chain indexers derive the account's bank-side balance
    // movement by negating it. Funding settlement changes position margin
    // WITHOUT moving the bank and is reported by AccountSettlementUpdate —
    // folding it in here would phantom-credit the off-chain bank-side
    // balance.
    //
    // Note the prev/updated snapshot asymmetry across margin ops: here
    // prevPosition is PRE-settlement (captured before the deposit and the
    // settle the deposit may newly cover), while removeMargin and
    // adjustLeverage settle first and snapshot prev AFTER settlement. In
    // both shapes the settle delta is carried by the
    // AccountSettlementUpdate emitted in between, so consumers must not
    // derive funding from prev-vs-updated diffs of this event alone.
    int256 marginDelta = int256(uint256(_amount));

    emit AccountPositionUpdate(
      _account,
      msgSender(),
      updatedBal,
      prevPosition,
      Action.ADD_MARGIN,
      globalIndex.value,
      _blockTimestamp(),
      marginDelta
    );
  }

  /**
   * @notice Allows caller to remove margin from an account's position
   * @param _account address of the account to remove margin from
   * @param _amount amount of margin to be removed
   * @param _nonce unique nonce to prevent replay attacks
   * @param _deadline last block timestamp at which the authorization is valid
   * @param _signature EIP-712 signature from a signer authorized for the account
   *  in this market
   * @dev Signature verification accepts the account owner, a sub-account the owner
   *      approved, or a system-account operator with permission in this market,
   *      but not a reduce-only operator.
   *      Settlement operator submits the transaction, but funds move based on user's signature.
   */
  function removeMargin(
    address _account,
    uint128 _amount,
    uint128 _nonce,
    uint64 _deadline,
    TypedSignature.Signature calldata _signature
  ) public onlySettlementOperator notDelisted nonReentrant whenTradingAllowed {
    require(_amount > 0, 'P15');
    address signer = ISignatureVerifier(addresses.signatureVerifier)
      .recoverMarginSigner(
        address(this),
        _account,
        _amount,
        false,
        _nonce,
        _deadline,
        _signature
      );
    _consumeMarginAuthorization(_account, signer, _nonce, _deadline);
    // Reduce-only may not withdraw margin from the position.
    _requireNotReduceOnly(_account, signer);

    Types.Context memory context = _loadContext(false);
    _removeMarginFromSettledAccount(context, _account, _amount, _amount);
  }

  /**
   * @notice Allows caller to remove up to a signed maximum from an account's position
   * @param _account address of the account to remove margin from
   * @param _maxAmount maximum amount of margin to remove
   * @param _minAmount minimum amount that must be removed for the transaction to succeed
   * @param _nonce unique nonce to prevent replay attacks
   * @param _deadline last block timestamp at which the authorization is valid
   * @param _signature EIP-712 signature from a signer authorized for the account
   *  in this market, other than a reduce-only operator
   * @dev This is intended for "remove max" flows that may race a funding-index refresh.
   *      Exact removals should continue using removeMargin.
   */
  function removeMarginUpTo(
    address _account,
    uint128 _maxAmount,
    uint128 _minAmount,
    uint128 _nonce,
    uint64 _deadline,
    TypedSignature.Signature calldata _signature
  ) public onlySettlementOperator notDelisted nonReentrant whenTradingAllowed {
    require(_maxAmount > 0, 'P15');
    require(_minAmount <= _maxAmount, 'P16');
    address signer = ISignatureVerifier(addresses.signatureVerifier)
      .recoverRemoveMarginUpToSigner(
        address(this),
        _account,
        _maxAmount,
        _minAmount,
        _nonce,
        _deadline,
        _signature
      );
    _consumeMarginAuthorization(_account, signer, _nonce, _deadline);
    // Reduce-only may not withdraw margin from the position.
    _requireNotReduceOnly(_account, signer);

    Types.Context memory context = _loadContext(false);
    _removeMarginFromSettledAccount(context, _account, _maxAmount, _minAmount);
  }

  function _removeMarginFromSettledAccount(
    Types.Context memory context,
    address _account,
    uint128 _maxAmount,
    uint128 _minAmount
  ) internal {
    _requireCurrentOracleFresh();

    // Settle pending funding FIRST so the removable bound, the margin
    // subtraction, and the ratio check below all see one settled balance.
    // Bounding on a settled copy while subtracting from the unsettled
    // stored margin would let a pending CREDIT authorize an amount the
    // stored margin cannot cover (uint128 underflow panic), and bounding
    // unsettled would approve margin a pending DEBIT is about to consume.
    _applyFundRateToAccount(context, _account);

    // get the (now funding-settled) position balance
    (Types.PositionBalance memory positionBalance, int256 fi) = packedAccounts[
      _account
    ].load();
    Types.PositionBalance memory prevPosition = _copyPositionBalance(
      positionBalance
    );

    uint128 maxRemovableAmount = IMarginMath(addresses.marginMath)
      .getMaxRemoveableMargin(positionBalance, context.price);
    if (_isBinaryFutureMarket() && !positionBalance.isPosPositive) {
      maxRemovableAmount = _getBinaryShortMaxRemovableMargin(positionBalance);
    }

    uint128 amount = BaseMath.min(_maxAmount, maxRemovableAmount);
    require(amount >= _minAmount, 'P16');
    require(amount > 0, 'P15');

    // transfer margin from perpetual address to acccount
    IMarginBank(addresses.marginBank).transferMarginToAccount(
      address(this),
      _account,
      amount
    );

    // update margin of user in storage
    positionBalance.margin -= amount;
    packedAccounts[_account].store(positionBalance, fi);

    // verify that imr/mmr checks still hold
    _verifyMarginRatioForAccount(
      _account,
      prevPosition,
      context.price,
      TRADER_ID,
      false,
      false
    );

    // marginDelta reports the position -> bank transfer (exactly the
    // removal): off-chain indexers derive the account's bank-side balance
    // movement by negating it. The settlement applied above changed
    // position margin without moving the bank and is reported by
    // AccountSettlementUpdate.
    int256 marginDelta = -int256(uint256(amount));

    emit AccountPositionUpdate(
      _account,
      msgSender(),
      positionBalance,
      prevPosition,
      Action.REMOVE_MARGIN,
      globalIndex.value,
      _blockTimestamp(),
      marginDelta
    );
  }

  /**
   * @notice Allows caller to adjust/change leverage of an account's position
   * @param _account address of the account for which to adjust leverage
   * @param _leverage updated leverage to be set
   * @param _maxMarginIn maximum collateral the signer authorizes moving from
   *  their bank balance into the position for this adjustment
   * @param _minMarginOut minimum collateral the signer requires moving from
   *  the position back into their bank balance for this adjustment
   * @param _nonce unique nonce to prevent replay attacks
   * @param _deadline last block timestamp at which the authorization is valid
   * @param _signature EIP-712 signature from a signer authorized for the account
   *  in this market; a reduce-only operator may not raise leverage
   * @dev The collateral this moves is derived from live position, funding, and
   *  oracle state, not from the signed leverage alone. `_maxMarginIn` and
   *  `_minMarginOut` are the signer's bound on that state-dependent transfer
   *  (audit #42): without them the same signature authorizes an arbitrarily
   *  larger deposit once the position has grown.
   */
  function adjustLeverage(
    address _account,
    uint128 _leverage,
    uint128 _maxMarginIn,
    uint128 _minMarginOut,
    uint128 _nonce,
    uint64 _deadline,
    TypedSignature.Signature calldata _signature
  ) public onlySettlementOperator notDelisted nonReentrant whenTradingAllowed {
    require(_leverage > 0, 'P17');
    require(_leverage % BaseMath.baseUInt() == 0, 'P17');
    // The selected leverage may never imply a stored margin requirement below
    // `initialMarginRequired`, i.e. leverage is capped at
    // 1 / initialMarginRequired. Enforced here, before the MarginBank
    // transfers below, so an over-leveraged request cannot move tokens and
    // only then fail the post-state margin check. Nonce replay (P23) is
    // checked inside _consumeMarginAuthorization below.
    require(
      int256(uint256(BaseMath.baseUInt().baseDiv(_leverage))) >=
        initialMarginRequired,
      'P17'
    );
    address signer = ISignatureVerifier(addresses.signatureVerifier)
      .recoverLeverageSigner(
        address(this),
        _account,
        _leverage,
        _maxMarginIn,
        _minMarginOut,
        _nonce,
        _deadline,
        _signature
      );
    _consumeMarginAuthorization(_account, signer, _nonce, _deadline);

    Types.Context memory context = _loadContext(false);

    // apply funding rate and get updated position Balance
    Types.PositionBalance memory positionBalance = _applyFundRateToAccount(
      context,
      _account
    );
    Types.PositionBalance memory prevPosition = _copyPositionBalance(
      positionBalance
    );

    // Reduce-only may lower leverage but never raise it (audit #38). mro is the
    // inverse of leverage, so a SMALLER mro is more leverage on the same margin.
    // Deleveraging is left open because it only shrinks risk, and an account
    // with no position (mro 0) is unaffected either way.
    uint128 newMro = BaseMath.baseUInt().baseDiv(_leverage);
    if (
      _accountMarketPermission(_account, signer) ==
      Types.MarketPermission.REDUCE_ONLY
    ) {
      require(newMro >= positionBalance.mro, 'P69');
    }

    uint128 targetMargin = _getTargetMargin(
      positionBalance,
      _leverage,
      context.price
    );

    // Bound the state-dependent transfer against what the signer authorized.
    // The contract enforces exactly two things: the deposit may not exceed
    // `_maxMarginIn`, and the withdrawal may not fall below `_minMarginOut`.
    // Both are checked on every call, including when the recomputed transfer
    // is zero.
    //
    // MNX's clients build withdrawal intent with `_maxMarginIn = 0`, so drift
    // that flips a withdrawal into a deposit reverts 'P76'. Any withdrawal
    // returns collateral to the account's own bank balance and still has to
    // clear the margin-ratio checks below.
    uint128 marginIn = targetMargin > positionBalance.margin
      ? targetMargin - positionBalance.margin
      : 0;
    uint128 marginOut = positionBalance.margin > targetMargin
      ? positionBalance.margin - targetMargin
      : 0;
    if (newMro < positionBalance.mro || marginOut > 0) {
      _requireCurrentOracleFresh();
    }
    require(marginIn <= _maxMarginIn, 'P76');
    require(marginOut >= _minMarginOut, 'P77');

    // if user position has more margin than required for leverage, move extra margin back to bank
    if (marginOut > 0) {
      IMarginBank(addresses.marginBank).transferMarginToAccount(
        address(this),
        _account,
        marginOut
      );
    }
    // if user position has < margin than required target margin, move required margin from bank to perpetual
    else if (marginIn > 0) {
      IMarginBank(addresses.marginBank).transferMarginToAccount(
        _account,
        address(this),
        marginIn
      );
    }

    // update mro and margin via packed storage
    {
      (Types.PositionBalance memory bal, int256 fi) = packedAccounts[_account]
        .load();
      bal.mro = BaseMath.baseUInt().baseDiv(_leverage);
      bal.margin = targetMargin;
      packedAccounts[_account].store(bal, fi);

      // verify open-notional cap transition using old tier vs. new tier
      IEvaluator(addresses.evaluator).verifyOpenNotionalTransitionForAccount(
        _account,
        positionBalance,
        bal,
        context.price
      );

      // verify that imr/mmr checks still hold
      _verifyMarginRatioForAccount(
        _account,
        positionBalance,
        context.price,
        TRADER_ID,
        false,
        false
      );

      int256 marginDelta = int256(uint256(targetMargin)) -
        int256(uint256(positionBalance.margin));

      emit AccountPositionUpdate(
        _account,
        _msgSender(),
        bal,
        prevPosition,
        Action.ADJUST_LEVERAGE,
        globalIndex.value,
        _blockTimestamp(),
        marginDelta
      );
    }
  }

  //===========================================================//
  //        AUDIT #41 — ORDER-INDEPENDENT DELIST SETTLEMENT     //
  //===========================================================//

  /**
   * @notice Register accounts' frozen delist claims so that an insolvent
   * delisting allocates the shortfall PROPORTIONALLY instead of paying
   * whoever calls first (audit #41).
   *
   * @dev PERMISSIONLESS by design. Every claim is recomputed here from this
   * contract's own storage at the frozen delisting terms — the caller
   * supplies only which accounts to look at, never how much they are owed —
   * so a hostile caller cannot inflate, deflate, or redirect a claim. That
   * leaves OMISSION as the only possible attack, and omission is exactly
   * what a permissionless entry point lets anyone cure: if the operator's
   * sweep misses an account, any party at all can register it before owner
   * finalization or an unfinalized fallback ratio lock.
   *
   * Idempotent: an already-registered account is SKIPPED, not reverted, so
   * re-running the same full list after a partial failure is safe and costs
   * only the reads. Accounts with negative equity register at claim zero,
   * which keeps `registeredDelistClaimCount` equal to the enumeration tool's
   * claimant count for the runbook's count-parity check.
   *
   * Open from the moment of delisting until the owner finalizes the complete
   * population or an unfinalized positive fallback settlement locks the ratio.
   * Finalization closes registration before the funding grace, so the normal
   * path's denominator cannot change while the market is being funded.
   *
   * @param _accounts accounts to register, at most `MAX_DELIST_CLAIM_BATCH`
   */
  function registerDelistClaims(
    address[] calldata _accounts
  ) external afterDelisting nonReentrant {
    _registerDelistClaims(_accounts);
  }

  /**
   * @dev Shared registration primitive. Permissionless settlement invokes it
   * before the first ratio lock so every account submitted in that call is in
   * the denominator. Once the owner has finalized a complete population, or a
   * ratio is already locked, the submitted accounts are intentionally left
   * unchanged.
   */
  function _registerDelistClaimsForSettlement(
    address[] memory _accounts
  ) private {
    if (
      !_delistClaimsActive() ||
      delistClaimRatioLocked ||
      delistClaimsFinalizedAt != 0
    ) {
      return;
    }
    _registerDelistClaims(_accounts);
  }

  function _registerDelistClaims(address[] memory _accounts) private {
    require(_accounts.length <= MAX_DELIST_CLAIM_BATCH, 'P90');
    // A delisting that predates this implementation has no claim epoch. Fail
    // LOUDLY rather than skipping every account as already-registered, which
    // is what a zero epoch would otherwise do — see `delistEpoch`.
    require(_delistClaimsActive(), 'P92');
    // Registration closes at population finalization, before the ratio locks.
    // Otherwise a late claim could change the denominator during the funding
    // grace or dilute payouts after settlement started.
    require(!delistClaimRatioLocked && delistClaimsFinalizedAt == 0, 'P88');

    uint128 price = delistingPrice;
    int256 fundingIndexValue = delistIndex.value;
    uint128 epoch = delistEpoch;

    for (uint256 i = 0; i < _accounts.length; i++) {
      address account = _accounts[i];
      // Skip-not-revert. A stale entry from an aborted delisting has an older
      // epoch, so it does NOT match and is correctly re-registered here at the
      // current delisting's terms.
      if (delistClaims[account].epoch == epoch) {
        continue;
      }

      (bool hasStanding, uint128 claimE18Raw) = _delistClaimStanding(
        account,
        price,
        fundingIndexValue
      );
      // Silently ignore addresses with no standing — see `_delistClaimStanding`.
      // Skipping rather than reverting keeps mixed batches usable.
      if (!hasStanding) {
        continue;
      }

      delistClaims[account] = DelistClaim({
        epoch: epoch,
        amountE18Raw: claimE18Raw
      });
      registeredDelistClaimCount += 1;
      registeredDelistClaimTotalE18Raw += claimE18Raw;
      outstandingDelistClaimE18Raw += claimE18Raw;

      emit DelistClaimRegistered(
        account,
        claimE18Raw,
        registeredDelistClaimCount,
        registeredDelistClaimTotalE18Raw
      );
    }
  }

  /**
   * @notice Finalizes the complete frozen claimant population for this
   * delisting (audit #41).
   *
   * @dev Only the owner can make this attestation. The contract cannot
   * enumerate `packedAccounts`, while the owner-controlled delist workflow
   * already produces and verifies that enumeration before preparing this
   * transaction. Passing the expected epoch, count, and total makes the signed
   * intent explicit and prevents a stale preparation from finalizing a later
   * delist cycle or a different on-chain set. Once finalized, registration is
   * permanently closed for the epoch. Finalization before the original close
   * boundary starts the funding grace; late finalization receives no grace.
   */
  function finalizeDelistClaimPopulation(
    uint128 _expectedDelistEpoch,
    uint128 _expectedRegisteredCount,
    uint256 _expectedRegisteredTotalE18Raw
  ) external onlyOwner afterDelisting nonReentrant {
    require(_delistClaimsActive(), 'P92');
    // An unlocked ratio after fallback started proves every fallback close so
    // far had a zero gross claim: any positive registered total would have
    // locked the ratio before its position changed. Permit the owner to
    // finalize the complete remaining population in that narrow state. Since
    // fallback can start only after the original close boundary, this late
    // finalization adds no grace and cannot reopen the abort window.
    require(!delistClaimRatioLocked && delistClaimsFinalizedAt == 0, 'P88');
    require(
      delistEpoch == _expectedDelistEpoch &&
        registeredDelistClaimCount == _expectedRegisteredCount &&
        registeredDelistClaimTotalE18Raw == _expectedRegisteredTotalE18Raw,
      'P99'
    );

    uint128 finalizedAt = _blockTimestamp();
    delistClaimsFinalizedAt = finalizedAt;
    emit DelistClaimPopulationFinalized(
      delistEpoch,
      _expectedRegisteredCount,
      _expectedRegisteredTotalE18Raw,
      finalizedAt
    );
  }

  /**
   * @dev One account's gross claim at the frozen delisting terms, read from
   * storage only. Uses `_settledPositionEquity`, the same primitive the close
   * path reaches through `_applyFundRateToAccount` + `_positionEquity`, so a
   * registered snapshot and the payout it later authorizes cannot drift.
   *
   * `qPos == 0` returns zero to mirror the close path's own gate: an account
   * with no position is skipped by `closePositionForAccounts` and rejected by
   * `closePosition` ('P18'), so it has nothing to claim.
   */
  function _delistClaimStanding(
    address _account,
    uint128 _price,
    int256 _fundingIndexValue
  ) private view returns (bool hasStanding, uint128 claimE18Raw) {
    (Types.PositionBalance memory balance, int256 localIndex) = packedAccounts[
      _account
    ].load();

    // An address with NO position state whatsoever — never traded on this
    // market, or already fully settled — has no standing to register.
    //
    // Without this, anyone could register arbitrary addresses as zero-claim
    // entries and inflate `registeredDelistClaimCount` at will, which breaks
    // the operator's count-parity check against the enumeration artifact: the
    // count is the cheap tripwire for "did the sweep miss anyone?", and a
    // poisoned count makes it useless. Skipping costs the griefer's gas and
    // changes nothing on-chain — no counter, no total, no event.
    //
    // Genuine position-holders with NEGATIVE equity still register, at claim
    // zero. They are real claimants whose claim happens to round to nothing,
    // and counting them is what keeps parity with the artifact meaningful.
    if (balance.qPos == 0 && balance.margin == 0 && balance.oiOpen == 0) {
      return (false, 0);
    }

    // Mirrors the close path's own gate: no position means nothing to pay out,
    // even though the account still holds state worth counting.
    if (balance.qPos == 0) {
      return (true, 0);
    }

    return (
      true,
      BaseMath.toPositive(
        _settledPositionEquity(balance, localIndex, _price, _fundingIndexValue)
      )
    );
  }

  /**
   * @notice Whether the audit #41 claim mechanism governs this delisting.
   *
   * @dev False on a market that was already delisted when this implementation
   * was upgraded in (`delistEpoch == 0`), where the legacy close path settles
   * unchanged. True for every delisting opened after the upgrade. Operator
   * tooling reads this to know which settlement procedure applies.
   */
  function delistClaimsActive() external view returns (bool) {
    return _delistClaimsActive();
  }

  function _delistClaimsActive() private view returns (bool) {
    return delistEpoch != 0;
  }

  /**
   * @notice Timestamp at which delist claims open for settlement.
   *
   * @dev Epoch-zero and unfinalized delistings keep the original close-delay
   * boundary. Owner finalization before that boundary opts the current epoch
   * into the fixed funding grace. A late finalization receives no grace and
   * therefore cannot pause permissionless settlement after it has opened.
   * This preserves a bounded permissionless exit if the owner becomes
   * unavailable after delisting, while the normal operator path gets an
   * immutable complete denominator before funding and settlement.
   */
  function delistClaimsOpenAt() public view returns (uint128) {
    if (!delisted) {
      return 0;
    }
    uint128 openAt = delistedAt + delistCloseDelaySeconds;
    if (
      _delistClaimsActive() &&
      delistClaimsFinalizedAt != 0 &&
      delistClaimsFinalizedAt < openAt
    ) {
      uint128 finalizedGraceEnd = delistClaimsFinalizedAt +
        DELIST_CLAIM_FUNDING_GRACE_SECONDS;
      if (finalizedGraceEnd > openAt) {
        openAt = finalizedGraceEnd;
      }
    }
    return openAt;
  }

  /**
   * @notice The collateral actually distributable to claims, and the fee
   * reserve that survives subordination, as they stand right now.
   *
   * @dev FEE SUBORDINATION. Protocol fees are retained only out of collateral
   * IN EXCESS of the registered claims, so when the market is short the fee
   * pool absorbs the loss BEFORE any user claim is reduced. Three regimes:
   *
   *  - collateral >= claims + fees  -> full fees retained, pot covers claims,
   *    ratio locks at 1e18. Identical to today.
   *  - claims <= collateral < claims + fees -> fees partially absorbed, pot
   *    equals the claims exactly, ratio still 1e18. Users whole, fees cut.
   *  - collateral < claims -> fees fully absorbed, pot is all the collateral,
   *    ratio below 1e18 and users share the remaining loss pro rata.
   *
   * @return potE18Raw collateral available to pay claims
   * @return retainedFeeE18Raw fee reserve surviving subordination
   */
  function delistClaimDistribution()
    public
    view
    returns (uint256 potE18Raw, uint128 retainedFeeE18Raw)
  {
    uint256 collateral = uint256(
      IMarginBank(addresses.marginBank).getAccountBankBalance(address(this))
    );
    uint256 claimsTotal = registeredDelistClaimTotalE18Raw;
    uint256 excess = collateral > claimsTotal ? collateral - claimsTotal : 0;
    retainedFeeE18Raw = uint128(
      excess < uint256(feePoolAccruedAmt) ? excess : uint256(feePoolAccruedAmt)
    );
    potE18Raw = collateral - uint256(retainedFeeE18Raw);
  }

  /**
   * @notice Shortfall between the registered claims and the collateral
   * available to pay them. Zero means the delisting is fully funded and the
   * ratio will lock at 1e18.
   *
   * @dev This is the operator's CHAIN-AUTHORITATIVE funding signal: the
   * amount to deposit into this market's MarginBank balance during the grace
   * window to honor the standing full-recapitalization policy. It already
   * accounts for fee subordination, so it is the true user-facing shortfall,
   * not the fee-inclusive figure.
   */
  function delistClaimShortfallE18Raw() external view returns (uint256) {
    (uint256 potE18Raw, ) = delistClaimDistribution();
    uint256 claimsTotal = registeredDelistClaimTotalE18Raw;
    return claimsTotal > potE18Raw ? claimsTotal - potE18Raw : 0;
  }

  /**
   * @notice The ratio that WOULD lock if claims opened now, in e18.
   * @dev Lets the operator confirm a deposit landed and restored a 1e18
   * outcome before the window closes. After the lock, reads the stored ratio.
   */
  function projectedDelistClaimRatioE18() external view returns (uint128) {
    if (delistClaimRatioLocked) {
      return delistClaimRatioE18;
    }
    (uint256 potE18Raw, ) = delistClaimDistribution();
    return _delistClaimRatioFor(potE18Raw, registeredDelistClaimTotalE18Raw);
  }

  /**
   * @dev `min(1e18, pot / total)` in e18 fixed point. A finalized population
   * with zero aggregate positive equity yields 1e18. Its registered positions
   * each have a zero claim, so this cannot distribute collateral to them.
   *
   * `potE18Raw` is bounded by a uint128 bank balance, so the numerator is at
   * most ~3.4e56 and cannot overflow uint256.
   */
  function _delistClaimRatioFor(
    uint256 _potE18Raw,
    uint256 _claimsTotalE18Raw
  ) private pure returns (uint128) {
    if (_claimsTotalE18Raw == 0) {
      return BaseMath.BASE_UINT;
    }
    uint256 ratio = (_potE18Raw * uint256(BaseMath.BASE_UINT)) /
      _claimsTotalE18Raw;
    return
      ratio >= uint256(BaseMath.BASE_UINT)
        ? BaseMath.BASE_UINT
        : uint128(ratio);
  }

  /**
   * @dev Fixes the payout ratio for this delisting, exactly once, on the
   * first settlement after claims open at which the registered total is
   * positive or the owner has finalized the population. Before that (an
   * unfinalized all-zero set) settlement closes zero-claim positions with the
   * ratio unlocked and registration still open. Once locked, every payout is
   * pure arithmetic on a constant, which is what makes settlement order
   * irrelevant.
   *
   * There is NO top-up-and-recompute path. Raising the ratio after payouts
   * had begun would pay late claimants more than early ones — the very
   * unfairness this fixes, merely inverted. The grace window before this
   * lock is the funding window.
   */
  function _lockDelistClaimRatioIfNeeded() private {
    // A delisting that predates this implementation never engages the
    // mechanism: no ratio is locked, no fee is written down, and settlement
    // falls through to the legacy payout. Leaving the ratio unlocked also
    // keeps `sweepDelistClaimResidual` shut on such a market.
    if (!_delistClaimsActive()) {
      return;
    }
    if (delistClaimRatioLocked) {
      return;
    }

    // An unfinalized zero-total set is not a binding denominator. Leave the
    // ratio unlocked so a zero-claim holder can still clear its position
    // without making 1e18 authoritative for positive claimants omitted from
    // that call. Owner finalization may lock a verified all-zero population.
    if (registeredDelistClaimTotalE18Raw == 0 && delistClaimsFinalizedAt == 0) {
      return;
    }

    (uint256 potE18Raw, uint128 retainedFeeE18Raw) = delistClaimDistribution();
    uint128 feesAbsorbedE18Raw = feePoolAccruedAmt - retainedFeeE18Raw;

    // Realize fee subordination in storage. The close path values its
    // collateral cap as `bankBalance - feePoolAccruedAmt`; leaving the full
    // accrual standing would let a fee reserve this market can no longer
    // afford starve the very payouts the ratio was derived from.
    if (feesAbsorbedE18Raw > 0) {
      feePoolAccruedAmt = retainedFeeE18Raw;
    }

    delistClaimRatioE18 = _delistClaimRatioFor(
      potE18Raw,
      registeredDelistClaimTotalE18Raw
    );
    delistClaimRatioLocked = true;

    emit DelistClaimRatioLocked(
      delistClaimRatioE18,
      potE18Raw,
      registeredDelistClaimTotalE18Raw,
      retainedFeeE18Raw,
      feesAbsorbedE18Raw
    );
  }

  /**
   * @notice Sweeps the post-settlement residual to the backstop vault.
   *
   * @dev Only reachable once every registered positive claim has been settled
   * (`outstandingDelistClaimE18Raw == 0`; zero-claim registrations never count
   * toward it and are owed nothing), so it can never take value a registered
   * claimant is still owed. In the insolvent case the residue is
   * floor-rounding dust: under one wei per claimant from flooring each
   * payout, plus under `registeredDelistClaimTotalE18Raw / 1e18` wei from
   * flooring the ratio itself.
   *
   * Owner-gated: the runbook sweeps only after the enumeration tool confirms
   * that no open positions remain.
   */
  function sweepDelistClaimResidual() external onlyOwner nonReentrant {
    require(delistClaimRatioLocked, 'P89');
    require(outstandingDelistClaimE18Raw == 0, 'P89');
    require(backstopVault != address(0), 'P91');

    uint128 residual = IMarginBank(addresses.marginBank).getAccountBankBalance(
      address(this)
    ) - feePoolAccruedAmt;
    require(residual > 0, 'P91');

    IMarginBank(addresses.marginBank).transferMarginToAccount(
      address(this),
      backstopVault,
      residual
    );

    emit DelistClaimResidualSwept(backstopVault, residual);
  }

  /**
   * @notice Settles `_account`'s position at the frozen delisting terms and
   *  credits the payout to the account's own MarginBank balance (no tokens
   *  leave the MarginBank). The payout equals the account's value at those
   *  terms only when the delisting is fully funded: a registered claim is paid
   *  `claim x delistClaimRatioE18`, and an unregistered account is paid at
   *  most the collateral not reserved for unsettled registered claims. A
   *  position can only be closed once.
   * @param _account the address of account for which to close position
   */
  function closePosition(
    address _account
  ) external override onlyValidCaller(_account) afterDelistDelay nonReentrant {
    {
      (Types.PositionBalance memory checkBal, ) = packedAccounts[_account]
        .load();
      require(checkBal.qPos > 0, 'P18');
    }

    address[] memory accounts = new address[](1);
    accounts[0] = _account;
    _registerDelistClaimsForSettlement(accounts);
    _lockDelistClaimRatioIfNeeded();
    Types.Context memory context = _loadDelistSettlementContext();
    _closeSinglePositionAtDelistingPrice(context, _account);
  }

  /**
   * @notice Owner-driven batch close. Settles each open account at the
   * recorded `delistingPrice` and transfers each user's margin back into
   * their own MarginBank balance. Used by the operator delist + redeploy
   * workflow so users don't have to call `closePosition` themselves.
   *
   * Accounts whose position has already been closed (`qPos == 0`) are
   * silently skipped, so overlapping batches and re-runs are idempotent.
   * Per-account semantics are identical to `closePosition` — same
   * settlement math, same `PositionClosed` + `AccountPositionUpdate`
   * events, same `MarginBank.transferMarginToAccount` movement. The
   * caller is responsible for sizing batches under the block gas limit;
   * ~50 accounts per call is a comfortable starting target on MegaETH.
   *
   * @param _accounts list of accounts whose positions should be closed
   */
  function closePositionForAccounts(
    address[] memory _accounts
  ) external override onlyOwner afterDelistDelay nonReentrant {
    _registerDelistClaimsForSettlement(_accounts);
    _lockDelistClaimRatioIfNeeded();
    _closeAccountsAtDelistingPrice(_accounts);
  }

  /**
   * @notice Permissionless bulk settlement of registered delist claims
   * (audit #41).
   *
   * @dev Identical settlement semantics to `closePositionForAccounts` — same
   * primitive, same events, same locked ratio — but callable by anyone. The
   * operator normally settles the whole claimant set so users never have to
   * act. The owner-finalized path uses the verified complete population; if
   * the owner is unavailable, the original close-delay boundary remains a
   * fallback and this call registers every submitted account before locking.
   * Payouts always land in the named account's own MarginBank balance, so a
   * permissionless caller can move value only to its rightful owner and never
   * to itself.
   *
   * Skips accounts with nothing left to settle (`qPos == 0`), so re-running
   * a list after a partial failure is safe and cheap.
   *
   * An empty batch cannot lock, and an unfinalized zero-total batch leaves the
   * ratio unlocked. Epoch-zero legacy delistings retain their original
   * behavior on every close path.
   *
   * @param _accounts accounts to settle, at most `MAX_DELIST_CLAIM_BATCH`
   */
  function settleDelistClaims(
    address[] calldata _accounts
  ) external afterDelistDelay nonReentrant {
    require(
      _accounts.length > 0 && _accounts.length <= MAX_DELIST_CLAIM_BATCH,
      'P90'
    );
    _registerDelistClaimsForSettlement(_accounts);
    _lockDelistClaimRatioIfNeeded();
    _closeAccountsAtDelistingPrice(_accounts);
  }

  /**
   * @dev Shared batch body for `closePositionForAccounts` and
   * `settleDelistClaims`. Pulls the frozen delist context once so every
   * account in the batch settles against the same funding index, and skips
   * already-settled accounts so overlapping batches and re-runs are
   * idempotent.
   *
   * Caller must hold the `nonReentrant` lock, must have passed
   * `afterDelistDelay`. A verified or positive-claim population has locked the
   * payout ratio; an unfinalized all-zero batch can safely clear at zero while
   * leaving the ratio open for later positive claims.
   */
  function _closeAccountsAtDelistingPrice(address[] memory _accounts) private {
    Types.Context memory context = _loadDelistSettlementContext();
    for (uint256 i = 0; i < _accounts.length; i++) {
      address account = _accounts[i];
      (Types.PositionBalance memory checkBal, ) = packedAccounts[account]
        .load();
      if (checkBal.qPos == 0) {
        continue;
      }
      _closeSinglePositionAtDelistingPrice(context, account);
    }
  }

  /**
   * @dev Closes one account's position at `delistingPrice` and transfers
   * the resulting margin back to the user's MarginBank balance. Shared
   * between the user-driven `closePosition` and the owner-driven
   * `closePositionForAccounts` so the two paths can't drift.
   *
   * Caller must hold the `nonReentrant` lock and must have verified that
   * the perpetual is delisted and the account's position is non-empty
   * (the latter is enforced for the user-driven entry point via the
   * `P18` check; the batched entry point skips empty accounts upstream).
   */
  function _closeSinglePositionAtDelistingPrice(
    Types.Context memory context,
    address _account
  ) private {
    // Records that a real position began settling at the unfinalized
    // fallback boundary. No contract code reads this flag; it is exposed only
    // through its getter. Finalization cannot move `delistClaimsOpenAt()`
    // back into the future regardless, because fallback settlement starts
    // only at or after the original close boundary and `delistClaimsOpenAt()`
    // grants grace only to a finalization before that boundary.
    if (_delistClaimsActive() && delistClaimsFinalizedAt == 0) {
      delistFallbackSettlementStarted = true;
    }

    // Apply the funding rate to account
    Types.PositionBalance memory balance = _applyFundRateToAccount(
      context,
      _account
    );

    /// @dev SATURATING, not a plain subtraction. On a market with a claim
    /// epoch every positive payout happens after the ratio lock has clamped
    /// `feePoolAccruedAmt` to at most the collateral, so `min` is a no-op for
    /// it; the only closes that run before the lock are zero-claim fallback
    /// closes, which pay zero whatever `min` returns. On an epoch-0 market —
    /// one already delisted when this implementation was upgraded in — that
    /// lock deliberately never runs, so the full accrual stands. If it exceeds
    /// the balance, a checked subtraction here panics (0x11), and because
    /// EVERY settlement entry point evaluates this same line the market
    /// becomes permanently unsettleable with `abortDelist` long past its
    /// window. Saturating turns that unrecoverable brick into an honest zero
    /// payout that still closes the position.
    ///
    /// The close path cannot itself create this state — it pays at most
    /// `balance - fees`, so it always leaves the earmark intact. Reaching it
    /// requires value to leave through a path with no fee-earmark check
    /// (`_removeMarginFromSettledAccount`, or the trade funds flow), all of
    /// which are `notDelisted` and therefore run before the delisting freezes
    /// the state in.
    uint128 bankBalance = IMarginBank(addresses.marginBank)
      .getAccountBankBalance(address(this));
    uint128 perpBalance = bankBalance -
      BaseMath.min(feePoolAccruedAmt, bankBalance);

    /// @dev The account's gross equity at the frozen delist terms, floored at
    /// zero. `context` always comes from `_loadDelistSettlementContext()`, so
    /// `context.price` is `delistingPrice` and `context.index.value` is
    /// `delistIndex.value`, and the funding half of that valuation was applied
    /// into `balance` just above. Computing the gross claim with
    /// `_positionEquity` — the same primitive `_settledPositionEquity` ends
    /// with — keeps this payout and `accountFundingAdjustedEquity` on one
    /// formula, instead of the separate copy in `MarginMath.getMarginLeft`
    /// that the two could drift away from.
    uint128 grossClaim = BaseMath.toPositive(
      _positionEquity(balance, context.price)
    );

    /// @dev AUDIT #41 — order-independent settlement.
    ///
    /// A registered claim is paid its locked pro-rata share of the SNAPSHOT
    /// recorded at registration, never a share of whatever collateral happens
    /// to remain when this particular call lands. Because the ratio is fixed
    /// before the first payout and the snapshot cannot move (every
    /// margin-changing path is `notDelisted`), the payout for an account is a
    /// pure function of that account — settlement order is irrelevant, and
    /// the last claimant receives exactly the same fraction as the first.
    ///
    /// When the shortfall was funded during the grace window the ratio is
    /// `1e18` and `baseMul` returns the snapshot unchanged, so a funded
    /// delisting pays exactly what it paid before this mechanism existed.
    ///
    /// An UNREGISTERED account is a straggler: either the owner finalized an
    /// incomplete sweep, or an unfinalized positive subset used the liveness
    /// fallback and locked before this account was submitted. It settles only
    /// against collateral not reserved for unsettled registered claims, which
    /// the RESERVATION block below enforces; the `perpBalance` cap alone would
    /// not. It is never funded out of a registered claimant's share, so it
    /// cannot dilute the settled ratio.
    /// A zero epoch means this delisting predates the mechanism, so no account
    /// can be registered and every settlement takes the legacy branch below.
    /// The `epoch != 0` term is what stops an unwritten claim slot (which also
    /// reads zero) from being mistaken for a registration worth nothing.
    uint128 marginLeft;
    uint128 epoch = delistEpoch;
    DelistClaim memory claim = delistClaims[_account];
    if (epoch != 0 && claim.epoch == epoch) {
      marginLeft = BaseMath.baseMul(claim.amountE18Raw, delistClaimRatioE18);
      outstandingDelistClaimE18Raw -= claim.amountE18Raw;
      emit DelistClaimSettled(
        _account,
        claim.amountE18Raw,
        marginLeft,
        delistClaimRatioE18
      );
    } else {
      marginLeft = grossClaim;

      /// @dev AUDIT #41 — RESERVATION. Capping a straggler at `perpBalance`
      /// alone is not enough: on a ratio-locked market the balance still
      /// contains the collateral that backs every registered claim not yet
      /// settled. A straggler settling FIRST would take its whole gross claim
      /// out of that collateral, and registered claimants settling afterwards
      /// would receive less than `claim x ratio` — or nothing at all — while
      /// being marked fully settled. That is a direct loss of registered user
      /// funds, and it made the payout order-dependent again, which is the
      /// entire defect this mechanism exists to remove.
      ///
      /// So the collateral owed to registered claimants is carved out of what
      /// this path can see. `outstandingDelistClaimE18Raw` is the GROSS
      /// registered claim still unsettled, so the amount still owed at the
      /// locked ratio is that times the ratio. It shrinks as registered
      /// claimants settle, which is what lets the last straggler still collect
      /// the genuine leftover.
      ///
      /// Rounding is deliberately conservative: each registered payout floors
      /// individually, and a sum of floors never exceeds the floor of the sum,
      /// so reserving `floor(outstanding x ratio)` always covers what is
      /// actually owed. The straggler absorbs that rounding slack rather than
      /// a registered claimant absorbing a shortfall.
      if (delistClaimRatioLocked) {
        uint256 reserved = (outstandingDelistClaimE18Raw *
          uint256(delistClaimRatioE18)) / uint256(BaseMath.BASE_UINT);
        uint256 unreserved = uint256(perpBalance) > reserved
          ? uint256(perpBalance) - reserved
          : 0;
        if (uint256(marginLeft) > unreserved) {
          // Safe: `unreserved` is bounded above by `perpBalance`, a uint128.
          marginLeft = uint128(unreserved);
        }
      }
    }

    /// @dev Defense in depth. For a registered claimant this cap is
    /// UNREACHABLE: fee subordination writes `feePoolAccruedAmt` down at lock
    /// time to exactly what collateral in excess of the registered claims can
    /// support, so the sum of every ratio'd payout is bounded by the pot the
    /// ratio was derived from. It still guards the straggler path and any
    /// state this contract has not reasoned about.
    marginLeft = BaseMath.min(marginLeft, perpBalance);

    // set user position to zero
    (Types.PositionBalance memory prevBal, int256 fi) = packedAccounts[_account]
      .load();
    Types.PositionBalance memory prevPosition = _copyPositionBalance(prevBal);
    uint128 oldMargin = prevBal.margin;
    prevBal.qPos = 0;
    prevBal.oiOpen = 0;
    prevBal.margin = 0;
    packedAccounts[_account].store(prevBal, fi);

    // transfer margin to user account
    IMarginBank(addresses.marginBank).transferMarginToAccount(
      address(this),
      _account,
      marginLeft
    );

    emit PositionClosed(_account, marginLeft, _blockTimestamp());

    emit AccountPositionUpdate(
      _account,
      msgSender(),
      prevBal,
      prevPosition,
      Action.FINAL_WITHDRAWAL,
      context.index.value,
      _blockTimestamp(),
      -int256(uint256(oldMargin))
    );
  }

  /**
   * @notice Delists the perpetual at the current oracle price if it is within
   * the provided bounds.
   * Once delisted, settlement (`closePosition` / `closePositionForAccounts` /
   * `settleDelistClaims`) is held off until `delistClaimsOpenAt()`:
   * `delistCloseDelaySeconds` after `delistedAt`, or, if later, 12 hours
   * (`DELIST_CLAIM_FUNDING_GRACE_SECONDS`) after an owner finalization that
   * lands before that boundary. Until then the owner may still call
   * `abortDelist()` to unwind the delist if it was malicious.
   * @dev The current result of the price oracle must be between the two bounds supplied.
   * @param  _priceLowerBound  The lower-bound (inclusive) of the acceptable price range.
   * @param  _priceUpperBound  The upper-bound (inclusive) of the acceptable price range.
   */
  function delistPerpetual(
    uint128 _priceLowerBound,
    uint128 _priceUpperBound
  ) external onlyOwner notDelisted nonReentrant {
    // Finalize the global funding index and grab the settlement price.
    Types.Context memory context = _loadContext(true);

    // Check price bounds.
    require(context.price >= _priceLowerBound, 'P19');
    require(context.price <= _priceUpperBound, 'P20');

    _recordDelist(context.price, context.index);
  }

  /**
   * @notice Delists the perpetual at an explicit settlement price supplied by
   * the owner.
   * @dev Used for governance/admin settlement where the final price should be
   * frozen directly, without mutating the oracle. Final funding accrual is
   * still applied into `delistIndex` using the explicit settlement price, but
   * `globalIndex` is left untouched so an abort resumes trading from the
   * pre-delist funding ledger.
   * @param _settlementPrice  Final settlement price in e18 raw units.
   */
  function delistPerpetualAtSettlementPrice(
    uint128 _settlementPrice
  ) external onlyOwner notDelisted nonReentrant {
    require(_settlementPrice > 0, 'P21');
    if (_isBinaryFutureMarket()) {
      require(_settlementPrice <= PositionBalanceMath.BINARY_MAX_PRICE, 'P53');
    }

    Types.Context memory context = _loadDelistContextAtPrice(_settlementPrice);
    _recordDelist(context.price, context.index);
  }

  /**
   * @notice Cancels a delisting before the settlement window opens.
   * Lifts the delisting — `delisted` returns to false, the recorded
   * `delistingPrice`, `delistedAt`, and `delistIndex` are cleared, and
   * `trade()` et al. pass the 'P1' gate again. State changed while delisted
   * is not rolled back.
   *
   * @dev Normally callable until the exact boundary returned by
   * `delistClaimsOpenAt()`. Only finalization that lands BEFORE the original
   * close boundary extends abort through the funding grace. A late finalization
   * may follow a zero-claim fallback close that did not lock the ratio, so it
   * must never reopen abort on potentially mutated position state.
   *
   * Intended escape hatch for automated or operator-initiated delists that
   * should be cancelled within the configured settlement window.
   *
   * Reverts:
   *   'P2'  — not currently delisted
   *   'P41' — abort window has already expired (settlement is now allowed)
   */
  function abortDelist()
    external
    override
    onlyOwner
    afterDelisting
    nonReentrant
  {
    _requireDelistCloseDelayConfigured();
    uint128 originalCloseBoundary = delistedAt + delistCloseDelaySeconds;
    uint128 abortBoundary = originalCloseBoundary;
    if (
      delistClaimsFinalizedAt != 0 &&
      delistClaimsFinalizedAt < originalCloseBoundary
    ) {
      abortBoundary = delistClaimsOpenAt();
    }
    require(_blockTimestamp() < abortBoundary, 'P41');

    delisted = false;
    delistingPrice = 0;
    delistedAt = 0;
    delistIndex = Types.Index({timestamp: 0, value: 0});

    // Any audit #41 claims registered against this (now abandoned) delisting
    // were valued at a settlement price that no longer applies. Retire them
    // here rather than only on the next delist, so the aggregate claim state
    // (count, total, outstanding, ratio, finalization) never reports figures
    // for a delisting that was called off. Per-account `delistClaims` entries
    // are not cleared: the getter still returns them with their old epoch,
    // and they are inert only because that epoch no longer matches.
    _resetDelistClaimState();

    emit PerpetualDelistAborted(_blockTimestamp());
  }

  function setTrustedForwarder(address _trustedForwarder) external onlyOwner {
    _setTrustedForwarder(_trustedForwarder);
  }

  //===========================================================//
  //                          SETTERS
  //===========================================================//

  /**
   * @notice Sets a new contract address for the price oracle
   * @param  _oracle  The new contract address for the price oracle
   * @dev While trading is live the replacement's answer must sit within the
   * stricter of the two feeds' per-update movement caps ('P85'). Routine
   * updates are capped at `maxUpdateBps`, and the ADL replacement-capacity
   * proof above assumes the price cannot move further than that between
   * accepted rounds; a swap that jumps past the cap silently reprices every
   * open position and can carry max-leverage accounts past bankruptcy in a
   * single owner call. `_requireValidOracle` only vets the incoming feed in
   * isolation and says so — the old-versus-new transition is this policy.
   *
   * A genuinely discontinuous migration is not an ordinary `setOracle`, and
   * halting trading alone does NOT stop everything that consumes the price.
   * Since audit #86 a halt does freeze the index: `updateGlobalIndex()` and
   * `setFundingRate()` carry {whenIndexAdvancementAllowed}, so no third party
   * can settle the elapsed funding interval at the swapped price mid-halt.
   * But LiquidityVault deposit and withdraw net-asset-value reads still reach
   * `accountFundingAdjustedEquity`, which `tradingStatus` does not gate. The
   * operator sequence is therefore unchanged: pause funding first
   * (`Guardian.setFundingRateStatus`, which settles the interval at the OLD
   * price and then zeroes the rate — it is the guardian, so the halt gate
   * exempts it), pause the vault, halt trading, swap, then resume in reverse.
   *
   * Halting also lets this CONTINUITY check skip for an incumbent that has
   * died, gone stale, or drifted out of the payout domain — but such a feed
   * still fails the funding checkpoint below, so halting alone does not
   * replace a broken feed; the reviewed-cutoff route described next does.
   *
   * Before any of that, the elapsed funding interval is committed under the
   * OUTGOING oracle ('P21'/'P47'/'P48' if it cannot price it). Continuity and
   * the checkpoint answer different questions and are both required: the
   * checkpoint decides who owns the time BEFORE the swap, continuity decides
   * whether the price may jump AT it. A dead incumbent fails the checkpoint,
   * and the route through that is {emergencyStopTradingAtCutoff} — the
   * reviewed cutoff it commits is the checkpoint substitute, which is why the
   * checkpoint itself has no halt bypass. Skipping it silently would erase
   * elapsed funding, the exact defect this checkpoint prevents.
   */
  function setOracle(address _oracle) external onlyOwner nonReentrant {
    _requireFactoryOracle(_oracle);
    if (_isBinaryFutureMarket()) {
      require(
        tradingStatus != Types.GuardianStatus.ALLOWED,
        'Perpetual: halt binary market before oracle replacement'
      );
    }
    address previousOracle = addresses.oracle;
    uint128 batchesBeforeCheckpoint = batchesSinceGlobalIndexUpdate;

    // Commit everything the OLD oracle priced before the replacement can be
    // read. Without this the next index update would price the whole elapsed
    // interval at the replacement's answer.
    uint128 cutoff = _checkpointFundingInputs();

    (uint256 newAnswer, uint256 newUpdatedAt) = _requireValidOracle(_oracle);
    _requireAdlReplacementCapacityInvariant(
      _oracle,
      addresses.evaluator,
      _validateInitialMargin(initialMarginRequired),
      uint256(maintenanceMarginRequired),
      defaultMakerFee,
      defaultTakerFee
    );
    _enforceOracleReplacementContinuity(
      previousOracle,
      _oracle,
      newAnswer,
      newUpdatedAt
    );
    addresses.oracle = _oracle;

    // The checkpoint above cleared the trade budget on the strength of the
    // OUTGOING oracle's freshness. Letting that stand would hand a full fresh
    // window of un-block-time-checked trading to a replacement that never
    // passed the same test — `_requireValidOracle` deliberately does not
    // age-check it, because replacement continuity is a separate policy. So
    // the reset only survives if the replacement independently earns it, on
    // the same terms `setMaxBatchesPerGlobalIndexUpdate` uses.
    if (!_isOracleRoundFreshAt(_oracle, _blockTimestamp())) {
      batchesSinceGlobalIndexUpdate = batchesBeforeCheckpoint;
    }

    emit PriceOracleUpdate(_oracle);
    emit FundingInputTransition(
      FundingInputTransitionKind.ORACLE_REPLACED,
      previousOracle,
      _oracle,
      addresses.funder,
      addresses.funder,
      cutoff,
      globalIndex.value
    );
  }

  /**
   * @notice Sets a new contract address for the signature verifier.
   * @param  _signatureVerifier  The new SignatureVerifier contract address
   * @dev SignatureVerifier is deployed immutable and shared across markets, so
   * a schema change ships as a NEW verifier that each market must be pointed
   * at. Before audit #42 `addresses.signatureVerifier` was only ever written
   * by `initialize`, which left no on-chain path to adopt one — the fix would
   * have reached fresh stacks only.
   *
   * The implementation upgrade and this rotation MUST land in the same
   * campaign run, back-to-back per market. During any mismatch window all
   * four signed margin paths
   * (`addMargin`, `removeMargin`, `removeMarginUpTo`, `adjustLeverage`) revert,
   * because the implementation calls a recovery selector the paired verifier
   * does not expose. That is a liveness failure, not a safety one: no
   * authorization is mis-validated, and trading is unaffected.
   *
   * Mirrors `FundingOracle`'s guardian setter: reject the zero address and any
   * address with no deployed code, and emit the exact previous and new values
   * so a rotation audit can reconstruct the fleet's history.
   * `MarginBank.setSignatureVerifier` is weaker: it rejects only the zero
   * address, and its `WithdrawalAuthConfigUpdate` carries only the new value.
   */
  function setSignatureVerifier(
    address _signatureVerifier
  ) external onlyOwner nonReentrant {
    // Verbose strings rather than short codes: this is an owner-only admin
    // call, not a gas-sensitive path, and audit #42's allocated short-code
    // range (P76-P80) is fully consumed by the authorization checks. Matches
    // `MarginBank.setSignatureVerifier` and `FundingOracle`'s guardian setter.
    require(
      _signatureVerifier != address(0),
      'Perpetual: invalid signature verifier'
    );
    require(
      _signatureVerifier.code.length > 0,
      'Perpetual: signature verifier is not a contract'
    );
    address previousSignatureVerifier = addresses.signatureVerifier;
    addresses.signatureVerifier = _signatureVerifier;
    emit SignatureVerifierUpdate(previousSignatureVerifier, _signatureVerifier);
  }

  /**
   * @notice Sets a new contract address for the evaluator
   * @param  _evaluator  The new contract address for the evaluator
   */
  function setEvaluator(address _evaluator) external onlyOwner nonReentrant {
    require(_evaluator != address(0), 'P61');
    if (_isBinaryFutureMarket()) {
      _requireBinaryEvaluatorLocked(_evaluator);
    }
    _requireAdlReplacementCapacityInvariant(
      addresses.oracle,
      _evaluator,
      _validateInitialMargin(initialMarginRequired),
      uint256(maintenanceMarginRequired),
      defaultMakerFee,
      defaultTakerFee
    );
    addresses.evaluator = _evaluator;
    emit EvaluatorUpdate(_evaluator);
  }

  function setOracleMaxStalenessSeconds(
    uint128 _maxStalenessSeconds
  ) external onlyOwner {
    require(
      _maxStalenessSeconds > 0 || maxBatchesPerGlobalIndexUpdate == 0,
      'P60'
    );
    oracleMaxStalenessSeconds = _maxStalenessSeconds;
    emit OracleMaxStalenessUpdate(_maxStalenessSeconds);
  }

  /**
   * @notice Sets how many trade batches may run per fresh global-index check.
   * @dev This budget is load-bearing for oracle safety, not just throughput.
   * The trade path skips the future-dated round check to stay off volatile
   * block data (see `_requireOracleRoundNotFutureDated`), and relies on this
   * budget to force trading back through `updateGlobalIndex`, which does
   * compare against block time. Two consequences for operators:
   *
   * - Passing zero disables the budget and removes that forcing function.
   *   `initialize` leaves the budget at zero until the owner sets one, and
   *   MNX's off-chain deployment tooling (not in this repository) refuses to
   *   launch a market at zero.
   *
   *   Zero is nonetheless RETAINED on purpose, and should not be removed as
   *   dead configuration. When the oracle goes stale this fuse gates forced
   *   liquidation and automatic deleveraging as well as ordinary trades, so
   *   zero is the operator's lever for
   *   letting forced exits through during an oracle incident. Removing it
   *   would turn an oracle outage into an event where positions cannot be
   *   liquidated, at exactly the price dislocation where that matters most.
   *   Whether an outage should instead hard-stop trading is a risk-policy
   *   decision, not a cleanup.
   * - Setting a NONZERO budget clears `batchesSinceGlobalIndexUpdate`, which
   *   hands trading a fresh window. That reset is therefore gated on the same
   *   block-time oracle check `updateGlobalIndex` performs, so raising the cap
   *   on a market frozen at P59 cannot reopen trading on a stale, future-dated
   *   or invalid round; a round that is still fresh passes, as it would through
   *   `updateGlobalIndex`. If the oracle is the problem, resolve the oracle,
   *   not the budget.
   *
   *   The zero path is deliberately NOT gated: the emergency bypass has to
   *   stay reachable while the oracle is broken, since that is precisely when
   *   forced exits need to get through.
   */
  function setMaxBatchesPerGlobalIndexUpdate(
    uint128 _maxBatches
  ) external onlyOwner {
    require(_maxBatches == 0 || oracleMaxStalenessSeconds > 0, 'P60');

    if (_maxBatches != 0) {
      // Same pair `_loadContext(true)` runs before it resets the counter, so
      // the two reset paths grant a fresh window on identical terms. Owner-only
      // and rare, so the block-time read costs nothing that matters here.
      uint128 currentTimestamp = _blockTimestamp();
      (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
      ) = IPriceOracle(addresses.oracle).latestRoundData();
      _requireSupportedOraclePrice(price);
      _requireOracleRoundNotFutureDated(updatedAt, currentTimestamp);
      _requireFreshOracle(
        roundId,
        updatedAt,
        answeredInRound,
        currentTimestamp
      );
    }

    maxBatchesPerGlobalIndexUpdate = _maxBatches;
    emit MaxBatchesPerGlobalIndexUpdate(_maxBatches);
    _resetGlobalIndexBatchBudget(globalIndex.timestamp);
  }

  /**
   * @notice Hands the market over to a new funder contract.
   *
   * @dev A stopped-market handover, not a live setter. Trading must already be
   * stopped ('P70'), which is what makes the rest of the sequence safe:
   * `stopTrading` (or {emergencyStopTradingAtCutoff}) has already committed the
   * elapsed interval under the OLD funder at an explicit cutoff, and `trade()`
   * reverts 'P8' until the market is deliberately restarted. Rotating a live
   * market instead left three broken states reachable:
   *
   *  - a replacement naming a different provider passed silently, then
   *    reverted every funding install inside the provider gate;
   *  - a fresh replacement has `fundingStart == 0`, so no window was settable
   *    and the rate stayed zero — yet `startTrading` could not restart the
   *    schedule, because `tradingStartTime` was still set. The market kept
   *    trading with funding silently inactive;
   *  - an already-active replacement imported another market's start time,
   *    window, and rate.
   *
   * Requiring the stop closes the second directly: the only way back to
   * trading is `startTrading`, which calls `startFunding` and establishes the
   * replacement's schedule. Funding cannot resume silently at zero.
   *
   * `confirmProviderPairing()` is the funder's half of the handover. It can
   * only succeed when this Perpetual is the provider the funder already names,
   * and the funder itself asserts its schedule is clean — so a partially
   * configured relationship cannot be created from one side.
   *
   * @param  _funder  The address of the new funder contract.
   */
  function setFunder(address _funder) external onlyOwner nonReentrant {
    require(tradingStartTime == 0, 'P70');
    require(_funder != address(0), 'P71');
    require(_funder.code.length > 0, 'P71');

    address previousFunder = addresses.funder;

    // Always a no-op on a stopped market — the real checkpoint happened when
    // trading stopped. Called anyway so this transition reports the same
    // cutoff as every other one, rather than inventing a second notion of it.
    uint128 cutoff = _checkpointFundingInputs();

    require(IFundingOracle(_funder).provider() == address(this), 'P71');
    // A replacement wired to a different Guardian would silently take the
    // funding-status lever away from this market's Guardian: the on-chain /
    // off-chain switch would answer to a contract nobody here controls.
    require(
      IFundingOracle(_funder).guardianContract() == addresses.guardian,
      'P71'
    );
    if (_isBinaryFutureMarket()) {
      _requireBinaryFunderLocked(_funder);
    }
    IFundingOracle(_funder).confirmProviderPairing();

    addresses.funder = _funder;
    emit FundingOracleUpdate(_funder);
    emit FundingInputTransition(
      FundingInputTransitionKind.FUNDER_REPLACED,
      addresses.oracle,
      addresses.oracle,
      previousFunder,
      _funder,
      cutoff,
      globalIndex.value
    );
  }

  /**
   * @notice Operator escape hatch for the witnessed-bankruptcy trade gate
   * (audit #71). Passing `true` disables the 'P87' revert in `trade()`;
   * passing `false` re-arms it.
   *
   * @dev Required, not optional, mirroring the zero-batch bypass on
   * `setMaxBatchesPerGlobalIndexUpdate`: a gate with no lever turns a
   * stuck-flag bug — an account the clear path cannot verify, an oracle
   * incident that blocks `clearBankruptFlag`'s snapshot read — into a market
   * that refuses all new risk with no way out. Like zero there, `true` here
   * is the operator's lever, deliberately reachable while the oracle is
   * broken (this setter reads no oracle), and it does NOT touch the flag
   * set: flags, count, and events keep accumulating so the ledger of
   * witnessed bankruptcies stays intact and re-arming restores exactly the
   * gate state the market had.
   *
   * Owner-only rather than the guardian contract because the Guardian has no
   * forwarding surface for per-market setters beyond trading status, and the
   * modelled lever (the zero-batch bypass) is owner-only for the same
   * reason.
   */
  function setBankruptcyGateDisabled(bool _disabled) external onlyOwner {
    bankruptcyGateDisabled = _disabled;
    emit BankruptcyGateDisabledUpdate(_disabled);
  }

  /**
   * @notice Configures the minimum deficit `flagBankrupt` accepts.
   * @param _floorE18 The new floor, e18 raw USDM. Must be nonzero: zero
   * storage is the "use the compiled default" sentinel that keeps upgraded
   * proxies armed without ceremony, so a stored zero must only ever mean
   * "never configured". A zero floor would also admit rounding-scale
   * deficits, which is exactly what the floor exists to reject.
   */
  function setBankruptcyDeficitDustFloor(uint128 _floorE18) external onlyOwner {
    require(
      _floorE18 > 0,
      'Perpetual: bankruptcy deficit dust floor must be nonzero'
    );
    bankruptcyDeficitDustFloorE18 = _floorE18;
    emit BankruptcyDeficitDustFloorUpdate(_floorE18);
  }

  /**
   * @notice Sets a new Fee Pool contract.
   * @param  _feePool  The address that receives accrued fees in {transferAccruedFee}.
   */
  function setFeePool(address _feePool) public override onlyOwner nonReentrant {
    require(_feePool != address(0), 'P22');
    addresses.feePool = _feePool;
    emit FeePoolUpdate(_feePool);
  }

  /**
   * @notice Updates status of trading for this market
   * @param _newStatus status of trading for this market. If not allowed then no new trades can be placed
   */
  function setTradingStatus(
    Types.GuardianStatus _newStatus
  ) external override onlyGuardianContract nonReentrant {
    if (_newStatus == Types.GuardianStatus.ALLOWED) {
      _requireAdlReplacementCapacityInvariant(
        addresses.oracle,
        addresses.evaluator,
        uint256(initialMarginRequired),
        uint256(maintenanceMarginRequired),
        defaultMakerFee,
        defaultTakerFee
      );
    }
    tradingStatus = _newStatus;
  }

  /**
   * @notice Enable trading on the Perpetual.
   * @param _startingTime the timestamp at which trading will start
   */
  function startTrading(uint128 _startingTime) external onlyOwner nonReentrant {
    require(tradingStartTime == 0, 'P23');
    require(_startingTime > _blockTimestamp(), 'P24');

    IFundingOracle(addresses.funder).startFunding(_startingTime);

    tradingStartTime = _startingTime;

    emit TradingStarted(tradingStartTime);
  }

  /**
   * @notice Disable trading on the Perpetual.
   * @dev only admin can invoke this. `stopFunding()` resets the funder's rate
   * to zero, so the elapsed interval is committed under the old rate first;
   * otherwise that zero would be applied backwards over time one side had
   * already earned.
   */
  function stopTrading() external onlyOwner nonReentrant {
    uint128 cutoff = _checkpointFundingInputs();

    tradingStartTime = 0;
    IFundingOracle(addresses.funder).stopFunding();

    emit TradingStopped(_blockTimestamp());
    emit FundingInputTransition(
      FundingInputTransitionKind.TRADING_STOPPED,
      addresses.oracle,
      addresses.oracle,
      addresses.funder,
      addresses.funder,
      cutoff,
      globalIndex.value
    );
  }

  /**
   * @notice Stops trading when the live oracle can no longer produce a usable
   * checkpoint, committing the elapsed interval at an explicitly reviewed
   * cutoff instead of silently pricing it at zero or at replacement data.
   *
   * @dev This is the deliberate emergency transition {stopTrading} refuses to
   * improvise. `stopTrading` reverts while the oracle is dead, stale, future
   * dated, or out of the supported domain, because its checkpoint reads that
   * oracle. Here the owner supplies the three inputs the checkpoint would have
   * read — the instant to stop at, and the price and per-second funding rate
   * that governed the interval leading up to it — recorded in the emitted
   * {EmergencyFundingCutoffReviewed} and {FundingInputTransition} for review.
   *
   * Supplying the checkpoint's inputs by hand is a real power, so it is not
   * available on a healthy market. Four things bound it:
   *
   *  - Guardian must already have halted trading ('P73'). That is the declared
   *    emergency, it is the correct first response either way, and
   *    `Guardian.setTradingStatus` reaches this market without touching the
   *    oracle or funder — so a broken dependency can never make the halt
   *    unreachable. This is a two-key sequence: the hot guardian key declares
   *    the emergency, the owner commits the reviewed cutoff.
   *  - The cutoff instant cannot predate the last committed index or postdate
   *    the current block ('P86').
   *  - The cutoff price is held to the same domain rule as any oracle answer.
   *  - The rate is held to the funder's own per-second ceiling ('P74') and, on
   *    a binary market, to zero ('P75') — the one-way binary funding lock is
   *    not bypassable here. The ceiling read is a `try`: the dependency this
   *    path assumes broken is the ORACLE, and `maxFunding` is a plain storage
   *    getter on the funder, so a failure is unexpected. If it reverts inside
   *    the funder, the rate is left unbounded. The binary rule is enforced
   *    either way.
   *
   * Once stopped, `trade()` reverts 'P8' and the funder's rate is zero, so no
   * further interval accrues until the market is deliberately restarted.
   *
   * @param _cutoffTimestamp Instant to stop at. Must be at or after the last
   * committed index and no later than now.
   * @param _cutoffPrice     Reviewed price for the interval being committed.
   * @param _cutoffFundingRate Reviewed per-second funding rate for that
   * interval. Pass zero only when funding genuinely was zero.
   */
  function emergencyStopTradingAtCutoff(
    uint128 _cutoffTimestamp,
    uint128 _cutoffPrice,
    int256 _cutoffFundingRate
  ) external onlyOwner nonReentrant {
    require(tradingStartTime > 0, 'P72');
    require(tradingStatus != Types.GuardianStatus.ALLOWED, 'P73');
    require(_cutoffTimestamp >= globalIndex.timestamp, 'P86');
    require(_cutoffTimestamp <= _blockTimestamp(), 'P86');
    _requireSupportedOraclePrice(int256(uint256(_cutoffPrice)));
    _requireReviewedCutoffFundingRate(_cutoffFundingRate);

    Types.Index memory index = _computeFundingIndex(
      globalIndex,
      _cutoffFundingRate,
      int256(uint256(_cutoffPrice)),
      _cutoffTimestamp
    );
    globalIndex = index;
    emit GlobalIndexUpdate(index.value, index.timestamp);

    tradingStartTime = 0;
    IFundingOracle(addresses.funder).stopFunding();

    emit TradingStopped(_blockTimestamp());
    emit EmergencyFundingCutoffReviewed(
      _cutoffTimestamp,
      _cutoffPrice,
      _cutoffFundingRate,
      index.value
    );
    emit FundingInputTransition(
      FundingInputTransitionKind.EMERGENCY_TRADING_STOPPED,
      addresses.oracle,
      addresses.oracle,
      addresses.funder,
      addresses.funder,
      _cutoffTimestamp,
      index.value
    );
  }

  /**
   * @dev Bounds the owner-supplied cutoff rate {emergencyStopTradingAtCutoff}
   * commits. A binary market's funding is locked off one way, so no reviewed
   * rate may reopen it. Otherwise the rate is held to the same per-second
   * ceiling the funder would have applied: `maxFunding` is a per-window cap
   * and FundingOracle divides by the window length before storing.
   */
  function _requireReviewedCutoffFundingRate(
    int256 cutoffFundingRate
  ) private view {
    if (_isBinaryFutureMarket()) {
      require(cutoffFundingRate == 0, 'P75');
      return;
    }
    if (cutoffFundingRate == 0) {
      return;
    }

    uint128 maxFundingPerWindow;
    uint128 fundingRateWindow;
    bool ceilingReadable = true;
    try IFundingOracle(addresses.funder).maxFunding() returns (uint128 cap) {
      maxFundingPerWindow = cap;
    } catch {
      ceilingReadable = false;
    }
    try IFundingOracle(addresses.funder).FUNDING_RATE_WINDOW() returns (
      uint128 window
    ) {
      fundingRateWindow = window;
    } catch {
      ceilingReadable = false;
    }

    // Unreadable ceiling leaves the rate unbounded on purpose; see the
    // function docstring. A zero window would divide by zero.
    if (!ceilingReadable || fundingRateWindow == 0) {
      return;
    }
    require(
      uint256(BaseMath.absolute(cutoffFundingRate)) <=
        uint256(maxFundingPerWindow) / uint256(fundingRateWindow),
      'P74'
    );
  }

  /**
   * @notice Sets the AccountManager contract address
   * @dev Only callable by owner/admin
   * @param  _accountManager  The address of the AccountManager contract
   */
  function setAccountManager(address _accountManager) external onlyOwner {
    require(_accountManager != address(0), 'P20');
    address previousAccountManager = address(accountManager);
    accountManager = IAccountManager(_accountManager);
    emit AccountManagerUpdate(previousAccountManager, _accountManager);
  }

  /**
   * @notice Add or remove a Settlement Operator address.
   * @dev Must be called by the Perpetual admin. Emits the SettlementOperatorUpdate event.
   *
   * @param  _operator  The address for which to enable or disable Settlement operator privileges.
   * @param  _approved  True if approved, false if disapproved.
   */
  function setSettlementOperator(
    address _operator,
    bool _approved
  ) external onlyOwner nonReentrant {
    settlementOperators[_operator] = _approved;
    emit SettlementOperatorUpdate(_operator, _approved);
  }

  /**
   * @notice sets offchain funding rate operator
   * @param _newOperator address of new funding rate operator
   */
  function setOffChainFROperator(
    address _newOperator
  ) external onlyOwner nonReentrant {
    offchainFROperator = _newOperator;
    emit OffchainFROperatorUpdate(offchainFROperator);
  }

  function setBackstopVault(
    address _backstopVault
  ) external onlyOwner nonReentrant {
    backstopVault = _backstopVault;
    emit BackstopVaultUpdate(_backstopVault);
  }

  function setBackstopTriggerMarginFraction(
    uint128 _fraction
  ) external onlyOwner nonReentrant {
    require(_fraction <= BaseMath.baseUInt(), 'P40');
    backstopTriggerMarginFractionE18 = _fraction;
    emit BackstopTriggerMarginFractionUpdate(_fraction);
  }

  /**
   * @notice Attempts to transfer a positive-equity distressed position to the
   * backstop vault child selected for this market.
   * @dev The account must have equity greater than zero and strictly below the
   * configured backstop trigger, where the trigger is
   * `riskNotional * maintenanceMarginRequired * backstopTriggerMarginFractionE18`
   * and `riskNotional` is the binary-aware basis the canonical margin ratio
   * uses. On success, remaining isolated margin and positive residual equity
   * transfer with the position and are retained by the child as the insurance
   * fee for assuming its tail risk.
   */
  function attemptBackstopInheritance(
    address account
  )
    external
    onlySettlementOperator
    notDelisted
    nonReentrant
    whenTradingAllowed
    returns (bool)
  {
    // The in-trade inheritance probe rides trade()'s own guardian gate;
    // this external entrypoint needs the same one, since a proceeding
    // inheritance persists the target's funding-settled position.
    return _attemptBackstopInheritance(account);
  }

  function completeBackstopInheritance(
    bytes32 inheritanceId,
    address account,
    address inheritingChild,
    Types.PositionBalance calldata inheritedPosition,
    Types.Context calldata context,
    address sender
  ) external returns (bool) {
    require(msg.sender == address(this), 'P49');
    return
      _transferPositionToChildVault(
        inheritanceId,
        account,
        inheritingChild,
        inheritedPosition,
        context,
        sender
      );
  }

  /**
   * @notice Add or remove a Trader contract address.
   * @param  _trader  The address of contract.
   * @param  _approved  True if approved, false if disapproved.
   */
  function setTradeContract(
    address _trader,
    bool _approved
  ) external onlyOwner nonReentrant {
    //TODO implement EIP165
    tradeContracts[_trader] = _approved;
    emit TradeContractUpdate(_trader, _approved);
  }

  /**
   * @notice Sets the market's default taker fee parameter.
   * @param  _defaultTakerFee  The notional fee rate for nonbinary markets or
   *                        payout-variance coefficient for binary markets,
   *                        as a fixed-point number with 18 decimals.
   */
  function setDefaultTakerFee(
    uint128 _defaultTakerFee
  ) public override onlyOwner nonReentrant {
    // validate if fee is always less than or equal to 25%
    require(_defaultTakerFee <= BaseMath.MAX_TRADE_FEE, 'P25');
    if (maintenanceMarginRequired > 0 && initialMarginRequired > 0) {
      _requireAdlReplacementCapacityInvariant(
        addresses.oracle,
        addresses.evaluator,
        uint256(initialMarginRequired),
        uint256(maintenanceMarginRequired),
        defaultMakerFee,
        _defaultTakerFee
      );
    }
    defaultTakerFee = _defaultTakerFee;
    emit DefaultTakerFeeUpdate(_defaultTakerFee);
  }

  /**
   * @notice Sets the market's default maker fee parameter.
   * @param  _defaultMakerFee  The notional fee rate for nonbinary markets or
   *                        payout-variance coefficient for binary markets,
   *                        as a fixed-point number with 18 decimals.
   */
  function setDefaultMakerFee(
    uint128 _defaultMakerFee
  ) public override onlyOwner nonReentrant {
    // validate if fee is always less than or equal to 25%
    require(_defaultMakerFee <= BaseMath.MAX_TRADE_FEE, 'P26');
    if (_isBinaryFutureMarket()) {
      require(
        _defaultMakerFee == 0,
        'Perpetual: binary maker fee must be zero'
      );
    }
    if (maintenanceMarginRequired > 0 && initialMarginRequired > 0) {
      _requireAdlReplacementCapacityInvariant(
        addresses.oracle,
        addresses.evaluator,
        uint256(initialMarginRequired),
        uint256(maintenanceMarginRequired),
        _defaultMakerFee,
        defaultTakerFee
      );
    }
    defaultMakerFee = _defaultMakerFee;
    emit DefaultMakerFeeUpdate(_defaultMakerFee);
  }

  /**
   * @notice Installs the funding rate for the current window.
   * @dev Updates the global index at the OUTGOING rate before installing, so
   * the elapsed interval is priced before the new rate takes effect.
   * Halt-gated with the guardian exemption; see {whenIndexAdvancementAllowed}.
   *
   * Operator-gated since audit #75/#90. This used to be a
   * permissionless poke: the funder derived the rate from its own state, so
   * who pushed the button did not matter. It now CARRIES the rate, and a
   * permissionless entrypoint would let anyone install any value inside the
   * cap. It shares `offchainFROperator` with {setOffChainFundingRate} because
   * both are now the same act — the exchange submitting a rate it computed —
   * differing only in which mode Guardian has the funder in.
   * @param fundingRate the rate for one whole funding window
   */
  function setFundingRate(
    int256 fundingRate
  )
    external
    onlyoffchainFROperator
    notDelisted
    nonReentrant
    whenIndexAdvancementAllowed
  {
    // update global index based on last funding rate
    _loadContext(true);

    // Set funding rate
    IFundingOracle(addresses.funder).setFundingRate(fundingRate);
  }

  /**
   * @notice Updates global funding index using current funding rate and oracle price.
   * @dev Useful as a lightweight pre-settlement call to keep settlement hot path deterministic.
   * Halt-gated with the guardian exemption; see {whenIndexAdvancementAllowed}.
   */
  function updateGlobalIndex()
    external
    notDelisted
    nonReentrant
    whenIndexAdvancementAllowed
  {
    uint128 previousTimestamp = globalIndex.timestamp;
    _loadContext(true);

    // A different transaction can advance the index earlier in this block.
    // Still acknowledge this successful refresh with the canonical event so
    // off-chain observers can terminalize the submitted transaction.
    if (globalIndex.timestamp == previousTimestamp) {
      emit GlobalIndexUpdate(globalIndex.value, globalIndex.timestamp);
    }
  }

  /**
   * @notice Applies pending funding to the given accounts at the current
   * global index.
   * @dev Permissionless: settlement is always-correct state maintenance. The
   * settlement math does not reject an account for a shortfall; credits add
   * to margin, debits consume margin, then positive unrealized profit, then
   * any remainder is written off. The call itself reverts on a delisted market
   * (P1), during a trading halt (P7), or when advancing the global index fails
   * its oracle checks, for example on a stale round.
   * Used by the off-chain funding-settlement keeper so funding debits cannot
   * silently outgrow collateral between organic touches.
   */
  function settleFundingForAccounts(
    address[] calldata accounts
  ) external notDelisted nonReentrant whenTradingAllowed {
    Types.Context memory context = _loadContext(true);
    for (uint256 i = 0; i < accounts.length; i++) {
      _applyFundRateToAccount(context, accounts[i]);
    }
  }

  /**
   * @notice Installs the funding rate while the off-chain funding mode is active.
   * @dev Updates the global index at the OUTGOING rate before installing, so
   * the elapsed interval is priced before the new rate takes effect.
   *
   * Halt-gated with the guardian exemption, the same as {setFundingRate} and
   * {updateGlobalIndex}. It advances the index through `_loadContext(true)`
   * just as they do, so audit #86's freeze has to cover it too — without the
   * gate this entrypoint was a way to keep advancing the index during a halt
   * that exists to stop exactly that.
   * @param offchainFundingRate the rate for one whole funding window
   */
  function setOffChainFundingRate(
    int256 offchainFundingRate
  )
    external
    onlyoffchainFROperator
    notDelisted
    nonReentrant
    whenIndexAdvancementAllowed
  {
    // update global index based on last funding rate
    _loadContext(true);

    // Set funding rate
    IFundingOracle(addresses.funder).setOffChainFundingRate(
      offchainFundingRate
    );
  }

  /**
   * @notice Sets a new value for the minimum collateralization percentage.
   * @param  _maintenanceMargin  The new maintenance margin requirement (the ratio
   *                        below which an account is undercollateralized), as a
   *                        fixed-point number with 18 decimals.
   */
  function setMaintenanceMargin(
    int256 _maintenanceMargin
  ) public onlyOwner nonReentrant {
    require(_maintenanceMargin > 0, 'P27');
    require(_maintenanceMargin <= initialMarginRequired, 'P28');

    _requireAdlReplacementCapacityInvariant(
      addresses.oracle,
      addresses.evaluator,
      uint256(initialMarginRequired),
      uint256(_maintenanceMargin),
      defaultMakerFee,
      defaultTakerFee
    );

    maintenanceMarginRequired = _maintenanceMargin;

    emit MMRUpdate(_maintenanceMargin);
  }

  /**
   * @notice Sets a new value for the initial margin collateralization percentage.
   * @param  _initialMargin  The new value of the initial margin collateralization percentage,
   *                        as a fixed-point number with 18 decimals.
   */
  function setInitialMargin(
    int256 _initialMargin
  ) public onlyOwner nonReentrant {
    uint256 imrRaw = _validateInitialMargin(_initialMargin);
    _requireAdlReplacementCapacityInvariant(
      addresses.oracle,
      addresses.evaluator,
      imrRaw,
      uint256(maintenanceMarginRequired),
      defaultMakerFee,
      defaultTakerFee
    );
    if (_isBinaryFutureMarket() && imrRaw != ADL_BASE) {
      // Once leverage may have created positions, the full-collateral
      // exemption cannot safely be restored by a later margin change.
      binaryFullCollateralBoundsEligible = false;
    }
    _setInitialMargin(_initialMargin);
  }

  function _setInitialMargin(int256 _initialMargin) internal {
    initialMarginRequired = _initialMargin;
    emit IMRUpdate(_initialMargin);
  }

  /**
   * @notice Transfers all accured fee from perpetual to fee pool
   *
   * @dev AUDIT #41 — blocked between a delisting and its ratio lock ('P93').
   *
   * Fee subordination decides how much of the fee reserve this market can
   * still afford only at lock time, writing `feePoolAccruedAmt` down to the
   * collateral in excess of the registered claims. Sweeping fees out during
   * the window ahead of that would move the money before the subordination
   * that is supposed to bind it, and an insolvent market would hand the fee
   * pool its full accrual while users took the entire loss — the exact
   * priority inversion the subordination exists to prevent.
   *
   * The window is narrow and self-closing: it opens at delist and ends the
   * moment the ratio locks, after which this transfers whatever the
   * subordination left. Markets that were never delisted, and markets
   * delisted before this mechanism shipped (`delistEpoch == 0`, settled by
   * the legacy path), are unaffected.
   */
  function transferAccruedFee() public onlyOwner nonReentrant {
    require(
      !delisted || !_delistClaimsActive() || delistClaimRatioLocked,
      'P93'
    );

    // transfer fee of trade to fee pool
    IMarginBank(addresses.marginBank).transferMarginToAccount(
      address(this),
      addresses.feePool,
      feePoolAccruedAmt
    );

    // reset fee amount accrued
    feePoolAccruedAmt = 0;
  }

  //===========================================================//
  //                          GETTERS
  //===========================================================//

  /**
   * @notice Get the balance of an account, without accounting for changes in the index.
   *
   * @param  account  The address of the account to query the balances of.
   * @return          The balances of the account.
   */
  function getAccountBalance(
    address account
  ) external view override returns (Types.PositionBalance memory) {
    (Types.PositionBalance memory balance, ) = packedAccounts[account].load();
    return balance;
  }

  /**
   * @notice Returns AccountManager's GLOBAL sub-account approval of `operator`
   * for `account`. This is not what this market authorizes against: signed
   * margin actions, `closePosition`, and IsolatedTrader orders use
   * {accountMarketPermission}, which ignores global approvals for system
   * accounts and treats an ordinary account as authorized for itself.
   *
   * @param  account   The account to query the operator for.
   * @param  operator  The address of the operator to query the status of.
   * @return           True if the operator is a sub account of the account, false otherwise.
   */
  function isSubAccount(
    address account,
    address operator
  ) public view override returns (bool) {
    return accountManager.isSubAccount(account, operator);
  }

  /**
   * @notice What `operator` may do for `account` in this market (audit #38).
   * @dev Public so IsolatedTrader authorizes against the same answer this
   * contract enforces, rather than deriving a second one that could drift.
   */
  function accountMarketPermission(
    address account,
    address operator
  ) public view override returns (Types.MarketPermission) {
    return _accountMarketPermission(account, operator);
  }

  /**
   * @dev What `operator` may do for `account` in THIS market (audit #38).
   *
   * For a vault-owned system account the answer is market-scoped and never
   * falls back to a global approval — a child trader holding one blanket
   * approval could otherwise sign in markets the vault never assigned it, and
   * the resulting position would move real assets without moving reported NAV.
   * For an ordinary user the answer is exactly the old global one.
   */
  function _accountMarketPermission(
    address account,
    address operator
  ) internal view returns (Types.MarketPermission) {
    return
      accountManager.accountMarketPermission(account, operator, address(this));
  }

  /**
   * @dev Validates a recovered signer independently of AccountManager so a
   * malformed signature can never become valid through a zero-address
   * approval or an overly permissive replacement AccountManager.
   *
   * Answers "may this signer act for this account here at all". Margin
   * removal additionally calls `_requireNotReduceOnly`; `adjustLeverage`
   * applies its own inline check that rejects only a leverage increase by a
   * reduce-only signer.
   */
  function _isValidAccountSigner(
    address account,
    address signer
  ) internal view returns (bool) {
    return
      signer != address(0) &&
      _accountMarketPermission(account, signer) != Types.MarketPermission.NONE;
  }

  /**
   * @dev Rejects any action by a reduce-only signer. Called only by
   * `removeMargin` and `removeMarginUpTo`; raising leverage is rejected
   * separately inside `adjustLeverage`, which must still let a reduce-only
   * signer lower leverage. Adding margin and closing never call this,
   * because a wind-down has to be able to reach zero.
   */
  function _requireNotReduceOnly(
    address account,
    address signer
  ) internal view {
    require(
      _accountMarketPermission(account, signer) !=
        Types.MarketPermission.REDUCE_ONLY,
      'P69'
    );
  }

  /**
   * @dev The shared deadline, nonce, and recovered-signer permission check for
   * every signed margin and leverage action (`addMargin`, `removeMargin`,
   * `removeMarginUpTo`, `adjustLeverage`); callers add the reduce-only
   * limits. Centralizing it keeps the four call sites from drifting; extend
   * this helper rather than re-deriving the condition.
   *
   * Marks the nonce consumed on success, so each authorization stays
   * single-use even when it sits above the account's minimum.
   *
   * Reading block time here is safe: all four callers are standalone account
   * transactions that already stamp `_blockTimestamp()` into their
   * `AccountPositionUpdate`. Nothing on the `trade()` path reaches this.
   */
  function _consumeMarginAuthorization(
    address account,
    address signer,
    uint128 nonce,
    uint64 deadline
  ) internal {
    require(_blockTimestamp() <= deadline, 'P78');
    require(nonce >= minimumMarginNonce[account], 'P79');
    require(!marginNonces[account][nonce], 'P23');
    require(_isValidAccountSigner(account, signer), 'P24');
    marginNonces[account][nonce] = true;
  }

  /**
   * @notice Cancels every unused margin/leverage authorization whose nonce is
   * below `_newMinimum`, in one transaction.
   * @param _newMinimum the lowest nonce this account will still honour
   * @dev Deliberately reachable while trading is halted or the market is
   * delisted: revoking a leaked authorization must never depend on market
   * state. Only the account itself can advance its own minimum — a leaked
   * sub-account key must not be able to grief the owner by advancing it.
   *
   * Uses `msgSender()` rather than `_msgSender()` so the account can revoke
   * through the trusted forwarder as a gasless meta-transaction, matching the
   * other user-initiated paths (`onlyValidCaller`).
   */
  function invalidateMarginNoncesUpTo(uint128 _newMinimum) external {
    address account = msgSender();
    require(_newMinimum > minimumMarginNonce[account], 'P80');
    minimumMarginNonce[account] = _newMinimum;
    emit MarginNoncesInvalidated(account, _newMinimum);
  }

  /**
   * @notice Gets the local funding index value for an account.
   *
   * @param  account   The account to query.
   * @return           The funding index value (int256).
   */
  function getLocalFundingIndex(
    address account
  ) external view returns (int256) {
    (, int256 fundingIndex) = packedAccounts[account].load();
    return fundingIndex;
  }

  /**
   * Returns true if trading is allowed for this market else false
   */
  function isTradingAllowed() external view override returns (bool) {
    return tradingStatus == Types.GuardianStatus.ALLOWED;
  }

  /**
   * @notice Returns the configured delay between delisting and settlement.
   * @dev Kept as a method named like the former constant so existing
   * off-chain callers can keep reading `CLOSE_DELAY()`.
   */
  function CLOSE_DELAY() external view returns (uint128) {
    return delistCloseDelaySeconds;
  }

  /**
   * @notice Returns true if this is a binary future market
   * @dev Binary markets have minPrice=1, maxPrice=1e18, maxFundingRate=0
   */
  function isBinaryFutureMarket() external view override returns (bool) {
    return _isBinaryFutureMarket();
  }

  function accountFundingAdjustedEquity(
    address account
  ) external view override returns (int256 equity) {
    (uint128 price, int256 fundingIndexValue) = _accountValuationTerms();
    return _accountEquityAt(account, price, fundingIndexValue);
  }

  function isAccountAdlEligible(address account) external view returns (bool) {
    (Types.PositionBalance memory balance, int256 localIndex) = packedAccounts[
      account
    ].load();
    if (balance.qPos == 0) {
      return false;
    }

    // Resolve the valuation terms — and, while the market is live, therefore
    // validate the oracle answer — before the binary max-loss shortcut. That
    // shortcut concludes a position can never go underwater, which holds only
    // while the answer stays inside the payout domain; consulting it first
    // would keep excluding the position from automatic deleveraging on exactly
    // the out-of-domain answer that invalidates it.
    //
    // On a live market this deliberately widens the shortcut's reverts to
    // round integrity and staleness (P47/P48) as well as the payout domain
    // (P67), because `_readOraclePrice` checks all of them. Staleness alone
    // does not break the max-loss argument, but erring toward a revert matches
    // `accountFundingAdjustedEquity`, and the off-chain deleveraging readers
    // treat a failed read as "keep the position pinned" rather than "safe".
    //
    // After delisting there is no live round to validate: the frozen
    // settlement price was already range-checked when it was recorded, and it
    // is the only price this position can still settle at.
    (uint128 price, int256 fundingIndexValue) = _accountValuationTerms();

    if (
      _isBinaryFutureMarket() &&
      PositionBalanceMath.hasBinaryMaxLossCollateralFloor(balance)
    ) {
      return false;
    }

    return
      _settledPositionEquity(balance, localIndex, price, fundingIndexValue) <=
      0;
  }

  /**
   * @notice The `flagBankrupt` deficit floor actually in force: the stored
   * `bankruptcyDeficitDustFloorE18` when configured, else the compiled
   * default. Zero storage is the sentinel every upgraded proxy wakes up
   * with, so the gate arms fleet-wide with a nonzero floor and no operator
   * ceremony (see the storage NatSpec).
   */
  function effectiveBankruptcyDeficitDustFloorE18()
    public
    view
    returns (uint128)
  {
    uint128 configuredFloor = bankruptcyDeficitDustFloorE18;
    return
      configuredFloor == 0
        ? DEFAULT_BANKRUPTCY_DEFICIT_DUST_FLOOR_E18
        : configuredFloor;
  }

  /**
   * @notice Permissionless, best-effort witness registration for bankrupt
   * accounts (audit #71). Per entry: the account is flagged iff
   * its equity — margin plus price PnL plus the pending-funding projection,
   * computed by `_accountEquityAt`, the SAME `_settledPositionEquity` math
   * the margin-ratio and settlement paths already trust — is strictly
   * negative, the deficit is at or above
   * `effectiveBankruptcyDeficitDustFloorE18()`, and the account is not
   * already flagged.
   *
   * Entries that fail verification or are already flagged are SKIPPED, not
   * reverted: the batch races liquidation by design, and an atomic batch
   * would revert the whole witness set whenever one account got liquidated
   * mid-flight. Callers must not treat transaction success as "all flags
   * landed" — read the `BankruptAccountFlagged` events or `bankruptFlagged`. The
   * only reverts are malformed input (empty or over-length batch) and the
   * oracle-read gates inside `_accountValuationTerms` (a dead, stale, or
   * out-of-domain feed reverts the whole call — the witness set must be
   * verified against one supported price snapshot, which also makes it
   * internally consistent).
   *
   * Adding and clearing a flag need no role: both are fully permissionless.
   * The owner holds two levers over the gate: `setBankruptcyDeficitDustFloor`
   * sets the minimum deficit this function admits (any nonzero value, so a
   * high floor stops new flags), and `setBankruptcyGateDisabled` turns off
   * the 'P87' trade check without touching the flag set. The gate acts on
   * flagged accounts: flagging is permissionless, and our keeper flags as part
   * of liquidation planning.
   *
   * Deliberately no `nonReentrant` and no market-state modifiers: every
   * external call is a view (a STATICCALL) — the oracle's `latestRoundData`,
   * plus the evaluator and funder bounds on a market whose binary-flag
   * migration has not run. The only state written is this contract's own
   * flag set, and a witness must be able to register during exactly the
   * distressed conditions — trading halts included — in which bankruptcies
   * happen.
   *
   * @param _accounts Accounts to verify and flag (at most
   * `MAX_BANKRUPTCY_FLAG_BATCH`).
   */
  function flagBankrupt(address[] calldata _accounts) external {
    require(_accounts.length > 0, 'Perpetual: empty bankruptcy flag batch');
    require(
      _accounts.length <= MAX_BANKRUPTCY_FLAG_BATCH,
      'Perpetual: bankruptcy flag batch too large'
    );

    // Hoist one oracle read and the global funding index for the whole
    // batch: every entry is verified against this single snapshot.
    (uint128 price, int256 fundingIndexValue) = _accountValuationTerms();
    uint128 dustFloor = effectiveBankruptcyDeficitDustFloorE18();

    for (uint256 i = 0; i < _accounts.length; i++) {
      address account = _accounts[i];
      if (bankruptFlagged[account]) {
        continue;
      }
      int256 equity = _accountEquityAt(account, price, fundingIndexValue);
      if (equity >= 0) {
        continue;
      }
      uint256 deficit = uint256(-equity);
      if (deficit < dustFloor) {
        continue;
      }
      bankruptFlagged[account] = true;
      bankruptFlaggedCount += 1;
      emit BankruptAccountFlagged(account, price, deficit);
    }
  }

  /**
   * @notice Permissionless, best-effort inverse of `flagBankrupt`: a flagged
   * account whose equity is no longer negative — because it was liquidated,
   * deleveraged, topped up, or the price recovered — is unflagged.
   * Still-bankrupt or unflagged entries are skipped. Anyone may call it: the
   * account owner after a top-up (so the action that defends the position
   * also clears its flag), our keeper after a liquidation pass, or an
   * arbitrary third party.
   *
   * The dust floor plays no part here: clear iff not bankrupt, exactly
   * symmetric with flag iff bankrupt. An account flagged at a large deficit
   * whose deficit shrinks below the floor but stays negative therefore stays
   * flagged — the floor is an admission filter against rounding-scale
   * deficits, not a hysteresis band. Flap (an account oscillating around
   * zero equity) churns events and someone's gas but cannot wedge anything.
   *
   * @param _accounts Flagged accounts to verify and clear (at most
   * `MAX_BANKRUPTCY_FLAG_BATCH`).
   */
  function clearBankruptFlag(address[] calldata _accounts) external {
    require(_accounts.length > 0, 'Perpetual: empty bankruptcy clear batch');
    require(
      _accounts.length <= MAX_BANKRUPTCY_FLAG_BATCH,
      'Perpetual: bankruptcy clear batch too large'
    );

    (uint128 price, int256 fundingIndexValue) = _accountValuationTerms();

    for (uint256 i = 0; i < _accounts.length; i++) {
      address account = _accounts[i];
      if (!bankruptFlagged[account]) {
        continue;
      }
      int256 equity = _accountEquityAt(account, price, fundingIndexValue);
      if (equity < 0) {
        // Still bankrupt at this snapshot; skip.
        continue;
      }
      bankruptFlagged[account] = false;
      // Cannot underflow: every true `bankruptFlagged` entry incremented the
      // count exactly once, and this branch requires the entry to be true.
      bankruptFlaggedCount -= 1;
      emit BankruptFlagCleared(account, price, equity);
    }
  }

  /**
   * @dev The (price, funding index) pair every account-equity read values an
   * account against: the live oracle price and live `globalIndex` while the
   * market trades, and the frozen `delistingPrice` and `delistIndex` once it is
   * delisted.
   *
   * After delisting the live oracle is deliberately not consulted at all. The
   * amount a position can still realize is fixed by `closePosition`, which
   * settles at exactly these frozen terms, so a later oracle move must not
   * change reported equity — that is what let `LiquidityVault.totalNAV` price
   * redemptions off value a delisted child position can never realize. Not
   * reading the feed also means a dead, incomplete, stale, or out-of-domain
   * round cannot block valuing a delisted market, which matters because
   * settlement itself never reads the oracle either: a feed that dies after
   * delisting must not brick reporting while closes keep working.
   *
   * `abortDelist` clears both frozen fields together with the `delisted` flag,
   * so an aborted delist resumes live valuation with no extra bookkeeping.
   */
  function _accountValuationTerms()
    internal
    view
    returns (uint128 price, int256 fundingIndexValue)
  {
    if (delisted) {
      return (delistingPrice, delistIndex.value);
    }
    return (_readOraclePrice(), globalIndex.value);
  }

  /**
   * @dev Account equity valued against an explicit (price, funding index) pair.
   * Neither input is read inside, so the caller chooses the valuation context:
   * live terms, frozen delist terms, or any other explicit pair a future caller
   * needs.
   */
  function _accountEquityAt(
    address account,
    uint128 price,
    int256 fundingIndexValue
  ) internal view returns (int256) {
    (Types.PositionBalance memory balance, int256 localIndex) = packedAccounts[
      account
    ].load();
    return
      _settledPositionEquity(balance, localIndex, price, fundingIndexValue);
  }

  /**
   * @dev The one account-equity calculation: settle pending funding from
   * `localIndexValue` to `fundingIndexValue` through `_settlePendingFunding`
   * (the single source of truth for funding-settlement math), then value the
   * settled position at the same `price`.
   *
   * `_closeSinglePositionAtDelistingPrice` runs the same two steps against the
   * frozen delist terms — `_applyFundRateToAccount` for the settlement half and
   * `_positionEquity` for the valuation half — so the pre-close view and the
   * gross close claim cannot drift apart.
   */
  function _settledPositionEquity(
    Types.PositionBalance memory balance,
    int256 localIndexValue,
    uint128 price,
    int256 fundingIndexValue
  ) internal pure returns (int256) {
    Types.PositionBalance memory adjustedBalance = _settlePendingFunding(
      balance,
      localIndexValue,
      fundingIndexValue,
      price
    ).balance;
    return _positionEquity(adjustedBalance, price);
  }

  /**
   * @dev Internal helper for binary market check. Upgraded markets fall back to
   * the old live-config fingerprint until their migration initializer runs; this
   * preserves trading and liquidation availability during a per-market rollout.
   */
  function _isBinaryFutureMarket() internal view returns (bool) {
    if (binaryFlagInitialized) {
      return isBinaryFutureMarketFlag;
    }
    return _inferBinaryFromLiveConfig();
  }

  function _inferBinaryFromLiveConfig() internal view returns (bool) {
    uint128 minPrice = IEvaluator(addresses.evaluator).minPrice();
    uint128 maxPrice = IEvaluator(addresses.evaluator).maxPrice();
    uint128 maxFundingRate = IFundingOracle(addresses.funder).maxFunding();
    return
      PositionBalanceMath.isBinaryBoundedMarket(
        minPrice,
        maxPrice,
        maxFundingRate
      );
  }

  function _requireBinaryEvaluatorLocked(address evaluator) internal view {
    IEvaluator nextEvaluator = IEvaluator(evaluator);
    require(
      nextEvaluator.minPrice() == PositionBalanceMath.BINARY_MIN_PRICE &&
        nextEvaluator.maxPrice() == PositionBalanceMath.BINARY_MAX_PRICE,
      'P64'
    );
    require(nextEvaluator.binaryMarketPriceBoundsLocked(), 'P64');
  }

  function _requireBinaryFunderLocked(address funder) internal view {
    IFundingOracle nextFunder = IFundingOracle(funder);
    require(nextFunder.maxFunding() == 0, 'P65');
    require(nextFunder.getFundingRate() == 0, 'P65');
    require(nextFunder.binaryMarketFundingLocked(), 'P65');
  }

  //===========================================================//
  //                      INTERNAL METHODS
  //===========================================================//

  function _transferMargin(address account, int256 fundsFlow) internal {
    (address src, address dest) = fundsFlow < 0
      ? (address(this), account)
      : (account, address(this));

    IMarginBank(addresses.marginBank).transferMarginToAccountSilent(
      src,
      dest,
      BaseMath.absolute(fundsFlow)
    );
  }

  function _readOraclePrice() internal view returns (uint128) {
    (
      uint80 roundId,
      int256 price,
      ,
      uint256 updatedAt,
      uint80 answeredInRound
    ) = IPriceOracle(addresses.oracle).latestRoundData();
    _requireSupportedOraclePrice(price);
    _requireFreshOracle(
      roundId,
      updatedAt,
      answeredInRound,
      globalIndex.timestamp
    );
    return uint128(uint256(price));
  }

  /// @return answer The validated positive, in-domain answer.
  /// @return updatedAt The validated round timestamp.
  /// @dev Returning the tuple lets `setOracle` run the replacement-continuity
  /// comparison on exactly the round this function validated, instead of
  /// re-reading `latestRoundData()` and measuring a possibly different — and
  /// unvalidated — round. `initialize` ignores both values.
  function _requireValidOracle(
    address oracle
  ) internal view returns (uint256 answer, uint256 updatedAt) {
    require(IPriceOracle(oracle).decimals() == ORACLE_PRICE_DECIMALS, 'P45');
    uint80 roundId;
    int256 price;
    uint80 answeredInRound;
    (roundId, price, , updatedAt, answeredInRound) = IPriceOracle(oracle)
      .latestRoundData();
    _requireSupportedOraclePrice(price);
    // This is the acceptance surface the whole round-metadata problem turns on.
    // Installation first requires an oracle created by ORACLE_FACTORY ('P94');
    // this check then validates its current round, so a misconfigured feed, a
    // milliseconds-instead-of-seconds unit bug, or malformed round metadata is
    // rejected before it can price a single trade. This path is owner-only and
    // rare, so reading block time costs nothing that matters.
    //
    // Max-age continuity for a replacement oracle is deliberately NOT enforced
    // here — that is the separate oracle-replacement continuity policy, not
    // this round-metadata gate.
    _requireValidOracleRound(roundId, updatedAt, answeredInRound);
    _requireOracleRoundNotFutureDated(updatedAt, _blockTimestamp());
    return (uint256(price), updatedAt);
  }

  /// @dev Second layer of the audit #79 fix. This is deliberately separate from
  /// `_requireValidOracle`: provenance establishes that the producer code is
  /// immutable, while the existing checks validate the particular round and
  /// market-specific movement bounds. Both are required.
  function _requireFactoryOracle(address oracle) internal view {
    require(ORACLE_FACTORY.isFactoryOracle(oracle), 'P94');
  }

  function _requireSupportedOraclePrice(int256 price) internal view {
    require(price > 0, 'P21');
    require(price <= int256(uint256(type(uint128).max)), 'P46');
    if (_isBinaryFutureMarket()) {
      require(
        price <= int256(uint256(PositionBalanceMath.BINARY_MAX_PRICE)),
        'P67'
      );
    }
  }

  function _validateInitialMargin(
    int256 marginRequirement
  ) internal view returns (uint256) {
    require(marginRequirement > 0, 'P29');
    require(marginRequirement >= maintenanceMarginRequired, 'P30');
    return uint256(marginRequirement);
  }

  /// @dev Binary markets spend maintenance-margin capacity across one oracle
  /// update, one worst-case execution, the variance-fee coefficient, and fixed
  /// rounding slack. Other market types retain the historical IMR-based proof.
  function _requireAdlReplacementCapacityInvariant(
    address oracle,
    address evaluator,
    uint256 imrRaw,
    uint256 mmrRaw,
    uint256 makerFeeRaw,
    uint256 takerFeeRaw
  ) internal view {
    if (oracle == address(0) || evaluator == address(0)) {
      return;
    }

    if (_isBinaryFutureMarket()) {
      (
        bool binaryBoundsReadable,
        uint256 oracleRiskFractionRaw,
        uint256 minUpdateIntervalSecondsRaw
      ) = _readBinaryOracleRisk(oracle);
      require(
        binaryBoundsReadable,
        'Perpetual: binary oracle bounds unreadable'
      );
      require(
        oracleRiskFractionRaw > 0 && oracleRiskFractionRaw <= ADL_BASE,
        'Perpetual: binary oracle risk fraction invalid'
      );
      require(
        minUpdateIntervalSecondsRaw ==
          uint256(ORACLE_FACTORY.BINARY_ORACLE_MIN_UPDATE_INTERVAL_SECONDS()),
        'Perpetual: binary oracle interval invalid'
      );

      uint256 takeRiskFractionRaw = uint256(
        IEvaluator(evaluator).binaryTakeRiskFraction()
      );
      require(
        takeRiskFractionRaw > 0 && takeRiskFractionRaw <= ADL_BASE,
        'Perpetual: binary take risk fraction invalid'
      );
      require(makerFeeRaw == 0, 'Perpetual: binary maker fee must be zero');
      require(
        imrRaw > 0 && imrRaw <= ADL_BASE && mmrRaw > 0 && mmrRaw <= imrRaw,
        'Perpetual: binary margins invalid'
      );

      // Only markets launched or explicitly migrated as full-collateral may
      // use the vacuous bound. Raising a live leveraged market's IMR does not
      // grandfather its existing positions into this exemption.
      if (
        imrRaw == ADL_BASE &&
        binaryFullCollateralBoundsEligibilityInitialized &&
        binaryFullCollateralBoundsEligible
      ) {
        return;
      }

      // Reserve the complete payout-variance fee coefficient. The fee is
      // `rate * p * (1 - p)` per unit; as a fraction of the risk notional that
      // maintenance margin measures, that is `rate * (1 - p)` for a long and
      // `rate * p` for a short, which approaches the full coefficient near the
      // payout bounds. Reserving the coefficient covers every price, which
      // keeps the replacement-capacity proof independent of the current price.
      uint256 reserveRaw = takerFeeRaw + BINARY_BOUND_ROUNDING_SLACK;
      require(
        reserveRaw < mmrRaw,
        'Perpetual: binary reserves exceed maintenance margin'
      );
      uint256 availableMovementRaw = mmrRaw - reserveRaw;
      uint256 remainingCapacityRaw = (ADL_BASE - oracleRiskFractionRaw) *
        (ADL_BASE - takeRiskFractionRaw);
      uint256 requiredRemainingCapacityRaw = ADL_BASE *
        (ADL_BASE - availableMovementRaw);
      require(
        remainingCapacityRaw >= requiredRemainingCapacityRaw,
        'Perpetual: binary replacement capacity exceeded'
      );
      return;
    }

    (bool readable, uint256 maxUpdateBps) = _readOracleMaxUpdateBps(oracle);
    require(readable, 'P54');
    require(maxUpdateBps > 0 && maxUpdateBps <= ADL_BPS_DENOMINATOR, 'P54');
    require(imrRaw > 0 && imrRaw <= ADL_BASE, 'P55');

    uint256 oracleMaxUpdateRaw = (maxUpdateBps * ADL_BASE) /
      ADL_BPS_DENOMINATOR;
    uint256 mtbLongRaw = uint256(IEvaluator(evaluator).mtbLong());
    uint256 mtbShortRaw = uint256(IEvaluator(evaluator).mtbShort());
    require(mtbLongRaw > 0 && mtbLongRaw < ADL_BASE, 'P56');
    require(mtbShortRaw > 0 && mtbShortRaw < ADL_BASE, 'P56');

    uint256 upwardRisk = (ADL_BASE + oracleMaxUpdateRaw) *
      (ADL_BASE + mtbLongRaw) *
      (ADL_BASE - imrRaw);
    require(upwardRisk <= ADL_REPLACEMENT_CAPACITY_SCALE, 'P57');

    uint256 downwardRisk = (ADL_BASE - oracleMaxUpdateRaw) *
      (ADL_BASE - mtbShortRaw) *
      (ADL_BASE + imrRaw);
    require(downwardRisk >= ADL_REPLACEMENT_CAPACITY_SCALE, 'P58');
  }

  /** Public pre-unpause assertion for upgrade and deployment runbooks. */
  function validateRiskConfiguration() external view returns (bool) {
    _requireAdlReplacementCapacityInvariant(
      addresses.oracle,
      addresses.evaluator,
      uint256(initialMarginRequired),
      uint256(maintenanceMarginRequired),
      defaultMakerFee,
      defaultTakerFee
    );
    return true;
  }

  function _readBinaryOracleRisk(
    address oracle
  )
    internal
    view
    returns (
      bool readable,
      uint256 riskFractionRaw,
      uint256 minUpdateIntervalSecondsRaw
    )
  {
    (bool riskSuccess, bytes memory riskData) = oracle.staticcall(
      abi.encodeWithSignature('riskFractionE18()')
    );
    (bool intervalSuccess, bytes memory intervalData) = oracle.staticcall(
      abi.encodeWithSignature('minUpdateIntervalSeconds()')
    );
    if (
      !riskSuccess ||
      riskData.length < 32 ||
      !intervalSuccess ||
      intervalData.length < 32
    ) {
      return (false, 0, 0);
    }
    return (
      true,
      abi.decode(riskData, (uint256)),
      abi.decode(intervalData, (uint256))
    );
  }

  /// @dev Reads a feed's advertised per-update movement cap in basis points.
  /// `readable` is false when the call reverts or returns under 32 bytes, as
  /// for a feed without `maxUpdateBps()`. Every non-binary market oracle must
  /// advertise a usable bound ('P54'); binary oracles return 0 here and are
  /// bounded by `riskFractionE18()` instead.
  function _readOracleMaxUpdateBps(
    address oracle
  ) internal view returns (bool readable, uint256 maxUpdateBps) {
    (bool success, bytes memory data) = oracle.staticcall(
      abi.encodeWithSignature('maxUpdateBps()')
    );
    if (!success || data.length < 32) {
      return (false, 0);
    }
    return (true, abi.decode(data, (uint256)));
  }

  /// @dev Strictest per-update movement bound advertised by the two feeds, in
  /// basis points, or 0 when neither exposes a usable one. A missing,
  /// disabled (0), or nonsensical (> 100%) bound means that feed is unlimited,
  /// so it is skipped rather than treated as the strictest.
  function _strictestOracleMovementBps(
    address oracleA,
    address oracleB
  ) internal view returns (uint256) {
    (bool readableA, uint256 bpsA) = _readOracleMaxUpdateBps(oracleA);
    (bool readableB, uint256 bpsB) = _readOracleMaxUpdateBps(oracleB);
    if (!readableA || bpsA == 0 || bpsA > ADL_BPS_DENOMINATOR) {
      bpsA = 0;
    }
    if (!readableB || bpsB == 0 || bpsB > ADL_BPS_DENOMINATOR) {
      bpsB = 0;
    }
    if (bpsA == 0) {
      return bpsB;
    }
    if (bpsB == 0) {
      return bpsA;
    }
    return bpsA < bpsB ? bpsA : bpsB;
  }

  /// @dev Non-reverting round read for the incumbent side of the continuity
  /// check. `usable` is false for a feed that reverts, returns short or
  /// malformed data, or reports a round `_isValidOracleRound` rejects or that
  /// is dated after the chain. Nothing this function observes can revert: the
  /// whole point of the halted-market path is that a dead or garbage incumbent
  /// can still be replaced.
  ///
  /// The returndata is decoded as five FULL words rather than as the declared
  /// `uint80`/`int256` tuple. Solidity's decoder checks that a `uint80` word
  /// has zero high bits and reverts with EMPTY returndata when it does not —
  /// no Panic code, and in THIS frame, so neither the staticcall's `success`
  /// flag nor a `try/catch` intercepts it. Every field occupies one word
  /// either way, so widening the two narrow ones and range-checking them by
  /// hand reads the same bytes and turns that revert into `usable == false`,
  /// which the live continuity path reports as 'P85'. The halted path never
  /// probes the incumbent; a dirty incumbent still fails `setOracle`'s funding
  /// checkpoint until `tradingStartTime` is zero (after
  /// {emergencyStopTradingAtCutoff}).
  function _readIncumbentOracleRound(
    address oracle,
    uint128 blockTimestamp
  ) internal view returns (bool usable, uint256 answer, uint256 updatedAt) {
    if (oracle == address(0)) {
      return (false, 0, 0);
    }

    (bool success, bytes memory data) = oracle.staticcall(
      abi.encodeWithSelector(IPriceOracle.latestRoundData.selector)
    );
    // A five-field tuple of static types encodes to exactly 160 bytes, so a
    // shorter return cannot be decoded and a longer one is read from the same
    // leading words.
    if (!success || data.length < 160) {
      return (false, 0, 0);
    }

    // Decoded as five full words, NOT as the declared `uint80`/`int256`
    // tuple. Every field occupies one word either way, but asking the decoder
    // for a `uint80` makes it assert the high bits are clear, and the two
    // narrow fields are range-checked by hand below instead.
    (
      uint256 roundIdWord,
      int256 rawAnswer,
      ,
      uint256 roundUpdatedAt,
      uint256 answeredInRoundWord
    ) = abi.decode(data, (uint256, int256, uint256, uint256, uint256));

    uint256 uint80Max = uint256(type(uint80).max);
    if (roundIdWord > uint80Max || answeredInRoundWord > uint80Max) {
      return (false, 0, 0);
    }

    if (
      !_isValidOracleRound(
        uint80(roundIdWord),
        roundUpdatedAt,
        uint80(answeredInRoundWord)
      )
    ) {
      return (false, 0, 0);
    }
    // Same rule as `_requireOracleRoundNotFutureDated`, in probe form.
    if (roundUpdatedAt > uint256(blockTimestamp)) {
      return (false, 0, 0);
    }
    // Not `_requireSupportedOraclePrice`: an incumbent that has drifted out of
    // the binary payout domain is still a real live valuation, and holding the
    // replacement close to it is strictly better than refusing to measure. The
    // replacement itself is already domain-checked by `_requireValidOracle`.
    if (rawAnswer <= 0 || uint256(rawAnswer) > uint256(type(uint128).max)) {
      return (false, 0, 0);
    }

    return (true, uint256(rawAnswer), roundUpdatedAt);
  }

  /// @dev Requires the old -> new oracle transition to be a move the market
  /// could have reached through ordinary capped updates, and records the
  /// transition either way.
  ///
  /// The comparison is skipped when there is nothing to keep continuous (no
  /// incumbent, or the same feed re-pointed) and when this market's trading
  /// status is not ALLOWED. A halted market is the governed migration path the
  /// audit recommendation names: stop the market, then checkpoint and cut over
  /// deliberately. It is also the only way to replace an incumbent that has
  /// died, gone stale, or drifted out of the payout domain, so this check can
  /// never brick a market. `PriceOracleReplaced.continuityProven == false` is
  /// the marker that such a transition happened.
  ///
  /// `tradingStatus` is read directly rather than through the guardian: it is
  /// the same state `isTradingAllowed()` exposes and `whenTradingAllowed`
  /// gates on, and reading it locally means a replaced guardian cannot widen
  /// the bypass. Note that a freshly initialized market is ALLOWED before it
  /// ever launches, so even a pre-launch re-point takes the halt round-trip.
  ///
  /// The halt remains the ONLY skip, deliberately, even though the funding
  /// checkpoint `setOracle` now runs first also gives up on a dead incumbent.
  /// A `tradingStartTime == 0` skip was considered and rejected: the emergency
  /// route that stops a market already requires a Guardian halt
  /// ({emergencyStopTradingAtCutoff}, 'P73') and the halt persists through it,
  /// so `tradingStatus != ALLOWED` already covers every state that route can
  /// reach. Adding the second skip would only have widened the bypass to
  /// pre-launch and plain-stopped markets, weakening this policy for no gain.
  ///
  /// Only `setOracle` reaches this, so reading block context is safe here; it
  /// is not on any path reachable from `trade()`. The replacement's round is
  /// the tuple `_requireValidOracle` already validated, passed in rather than
  /// re-read, so the comparison cannot measure a different round than the one
  /// that was checked.
  ///
  /// The incumbent is probed only AFTER the three short-circuits, so no
  /// property of the outgoing feed — not even a future decoding surprise —
  /// can stand between an operator and the halted escape hatch. The skipped
  /// paths therefore emit `previousAnswer == 0`; a zero there means "no
  /// comparison ran", matching `appliedMaxUpdateBps == 0`.
  function _enforceOracleReplacementContinuity(
    address previousOracle,
    address newOracle,
    uint256 newAnswer,
    uint256 newUpdatedAt
  ) internal {
    if (previousOracle == address(0) || previousOracle == newOracle) {
      // Nothing to compare against, and no live valuation moves as a result.
      // A same-address re-point is a true no-op, so it does not consume the
      // one-replacement-per-block allowance below.
      if (previousOracle != newOracle) {
        lastOracleReplacementBlock = block.number;
      }
      emit PriceOracleReplaced(
        previousOracle,
        newOracle,
        0,
        newAnswer,
        0,
        true
      );
      return;
    }

    if (tradingStatus != Types.GuardianStatus.ALLOWED) {
      lastOracleReplacementBlock = block.number;
      emit PriceOracleReplaced(
        previousOracle,
        newOracle,
        0,
        newAnswer,
        0,
        false
      );
      return;
    }

    // One replacement per block, mirroring the price oracles'
    // `lastUpdateBlock` rule for ordinary updates. A per-update cap bounds the
    // price only if updates cannot be chained atomically; no legitimate
    // migration needs two swaps in one block.
    require(lastOracleReplacementBlock < block.number, 'P85');

    uint128 nowTimestamp = _blockTimestamp();
    (
      bool previousUsable,
      uint256 previousAnswer,
      uint256 previousUpdatedAt
    ) = _readIncumbentOracleRound(previousOracle, nowTimestamp);

    // Fail closed when the incumbent cannot supply a baseline: without both
    // answers there is no transition to measure.
    require(previousUsable, 'P85');
    // Max age is deliberately left to this policy rather than
    // `_requireValidOracle` (see its comment). A stale answer on either side
    // is not evidence of where the market is.
    _requireOracleAgeWithinLimit(previousUpdatedAt, nowTimestamp);
    _requireOracleAgeWithinLimit(newUpdatedAt, nowTimestamp);

    // Hold the transition to whichever feed is stricter, so a swap can never
    // be used to spend the looser feed's allowance. A feed that exposes no
    // usable bound is unlimited and therefore never the stricter one; if
    // neither exposes one there is nothing to measure against and the call
    // fails closed. `setOracle` already requires a valid bound on the
    // replacement ('P54'), so in practice only a market whose oracle was
    // installed at `initialize` reaches the one-sided case, and it is held to
    // the incoming feed's cap.
    uint256 strictestBps = _strictestOracleMovementBps(
      previousOracle,
      newOracle
    );
    require(strictestBps > 0, 'P85');

    uint256 diff = newAnswer > previousAnswer
      ? newAnswer - previousAnswer
      : previousAnswer - newAnswer;
    // Exactly the product comparison ImmutableBackendPriceOracle.setPrice applies to an
    // ordinary capped update: no division, so no rounding slack either way.
    // Both operands are bounded by uint128 max * 10000, far inside uint256.
    require(diff * ADL_BPS_DENOMINATOR <= previousAnswer * strictestBps, 'P85');

    lastOracleReplacementBlock = block.number;
    emit PriceOracleReplaced(
      previousOracle,
      newOracle,
      previousAnswer,
      newAnswer,
      strictestBps,
      true
    );
  }

  /// @dev The round-metadata rules every `latestRoundData()` consumer runs:
  /// initialization, oracle replacement, trading, funding/index updates,
  /// liquidation, automatic deleveraging, and delisting. Keeping them in one
  /// place is what stops those paths from drifting into different rules.
  ///
  /// Deliberately `pure`: it reads no block context, so even the trade hot path
  /// can afford it. The upper timestamp bound lives in
  /// `_requireOracleRoundNotFutureDated` for exactly that reason.
  ///
  /// P47 covers every "the oracle round itself is unusable" state:
  ///   - `roundId == 0`             — the feed has never published a round.
  ///   - `answeredInRound < roundId` — a Chainlink-style round that was
  ///     started but never answered, so `answer`/`updatedAt` belong to an
  ///     older round. Chainlink permits `answeredInRound > roundId`, so only a
  ///     strictly lower value is incomplete.
  ///   - `updatedAt == 0`           — no publish timestamp at all.
  ///
  /// These are oracle-state faults, never caller faults, which is why they
  /// share the existing retryable-infrastructure P47 classification.
  function _requireValidOracleRound(
    uint80 roundId,
    uint256 updatedAt,
    uint80 answeredInRound
  ) internal pure {
    require(_isValidOracleRound(roundId, updatedAt, answeredInRound), 'P47');
  }

  /// @dev Boolean form of the rules above, for callers that have to probe a
  /// feed instead of reverting on it, all through `_readIncumbentOracleRound`.
  /// The replacement-continuity check reads the INCUMBENT, which may have
  /// degraded since it was installed, and a degraded incumbent must force the
  /// halted-market path rather than make `setOracle` uncallable.
  /// `_isOracleRoundFreshAt` uses the same probe for `setOracle`'s trade-budget
  /// decision and for `_requireCurrentOracleFresh` in `removeMargin`,
  /// `removeMarginUpTo`, and `adjustLeverage`. Kept as the single definition so
  /// the probes and the enforcing paths can never disagree about what a usable
  /// round is.
  function _isValidOracleRound(
    uint80 roundId,
    uint256 updatedAt,
    uint80 answeredInRound
  ) internal pure returns (bool) {
    return roundId != 0 && answeredInRound >= roundId && updatedAt != 0;
  }

  /// @dev Rejects a round dated after the chain: a feed reporting a future
  /// timestamp would otherwise read as perfectly fresh until that time
  /// arrives. The realistic trigger is a unit bug — an adapter returning
  /// milliseconds instead of seconds lands ~54,000 years ahead — not a feed
  /// that is merely wrong about the price.
  ///
  /// `blockTimestamp` is a PARAMETER rather than a `_blockTimestamp()` call so
  /// this can only run where the caller has already loaded block time: oracle
  /// installation/replacement, and the index-updating branch of
  /// `_loadContext`. It must never reach the trade hot path — MegaETH applies
  /// a much lower compute ceiling to transactions that touch volatile block
  /// data, and `trade()`'s own code avoids them (see the `settlementTimestamp`
  /// comment in `trade`). One nested exception: a backstop inheritance that
  /// exactly offsets the child's position can call
  /// `MarginBank.transferMarginToAccount`, whose event stamps
  /// `block.timestamp`. Installation is where a malformed feed actually
  /// enters, so gating it there is what closes the hole; `updateGlobalIndex`
  /// then re-checks an installed feed that degrades later.
  ///
  /// A nonzero `maxBatchesPerGlobalIndexUpdate` bounds how many trade batches
  /// can run on a round that no block-time check has seen; zero disables the
  /// budget. MNX's off-chain deployment tooling refuses to launch a market at
  /// zero.
  /// Setting a nonzero budget through `setMaxBatchesPerGlobalIndexUpdate`
  /// resets the counter only after the same block-time oracle check, so it
  /// cannot reopen trading on a stale, future-dated or invalid round; a round
  /// that is still fresh passes. Setting zero skips the check and disables
  /// the budget.
  function _requireOracleRoundNotFutureDated(
    uint256 updatedAt,
    uint128 blockTimestamp
  ) internal pure {
    require(updatedAt <= uint256(blockTimestamp), 'P47');
  }

  /// @dev Round integrity is enforced unconditionally;
  /// `oracleMaxStalenessSeconds == 0` disables only the maximum-age limit,
  /// never the checks above.
  /// `referenceTimestamp` is the caller's clock: current block time on
  /// index-updating paths, the cached `globalIndex.timestamp` on the trade hot
  /// path (see `_loadContext`).
  function _requireFreshOracle(
    uint80 roundId,
    uint256 updatedAt,
    uint80 answeredInRound,
    uint128 referenceTimestamp
  ) internal view {
    _requireValidOracleRound(roundId, updatedAt, answeredInRound);
    _requireOracleAgeWithinLimit(updatedAt, referenceTimestamp);
  }

  /// @dev The maximum-age half of `_requireFreshOracle`, split out for the
  /// replacement-continuity check, which has already established round
  /// validity separately (through `_requireValidOracle` for the incoming feed
  /// and `_readIncumbentOracleRound` for the outgoing one) and must not
  /// re-derive it from placeholder round numbers.
  function _requireOracleAgeWithinLimit(
    uint256 updatedAt,
    uint128 referenceTimestamp
  ) internal view {
    uint128 maxStalenessSeconds = oracleMaxStalenessSeconds;
    if (maxStalenessSeconds == 0) {
      return;
    }
    // A round at or ahead of the reference clock has zero age against it, and
    // on the trade hot path that is the NORMAL case: the cached index
    // timestamp legitimately lags a newer oracle round, so requiring the round
    // to be older would revert every trade between an oracle update and the
    // next index update.
    //
    // Callers that also ran `_requireOracleRoundNotFutureDated` have already
    // bounded `updatedAt` by real block time before reaching here. For the hot
    // path, `updateGlobalIndex` performs that check, and a nonzero trade-batch
    // budget forces it.
    if (updatedAt >= referenceTimestamp) {
      return;
    }
    // Subtraction is safe: `updatedAt < referenceTimestamp` here. The old
    // `updatedAt + maxStalenessSeconds >= referenceTimestamp` form could
    // overflow instead.
    require(
      uint256(referenceTimestamp) - updatedAt <= uint256(maxStalenessSeconds),
      'P48'
    );
  }

  /**
   * @dev Non-reverting form of the block-time freshness pair
   * `updateGlobalIndex` and `setMaxBatchesPerGlobalIndexUpdate` require.
   * {setOracle} must ask the question without failing on the answer because it
   * has to stay able to INSTALL a stale replacement — replacement continuity
   * is a separate policy that deliberately skips on a halted market (a
   * never-launched market is still ALLOWED and gets the full comparison) —
   * while still refusing to hand it a fresh trade budget.
   *
   * Reuses `_readIncumbentOracleRound` for the probe, so round integrity, the
   * future-dating bound, and the malformed-return handling are the same code
   * the continuity policy runs. Only the maximum-age comparison is restated,
   * and only because `_requireOracleAgeWithinLimit` reverts by design.
   */
  function _isOracleRoundFreshAt(
    address oracle,
    uint128 referenceTimestamp
  ) private view returns (bool) {
    (bool usable, , uint256 updatedAt) = _readIncumbentOracleRound(
      oracle,
      referenceTimestamp
    );
    if (!usable) return false;

    uint128 maxStalenessSeconds = oracleMaxStalenessSeconds;
    if (maxStalenessSeconds == 0) return true;
    if (updatedAt >= uint256(referenceTimestamp)) return true;
    return
      uint256(referenceTimestamp) - updatedAt <= uint256(maxStalenessSeconds);
  }

  function _requireCurrentOracleFresh() private view {
    require(_isOracleRoundFreshAt(addresses.oracle, _blockTimestamp()), 'P48');
  }

  /**
   * @dev The first two steps every funding-input transition shares: prove the
   * CURRENTLY installed oracle and funder are still usable, then commit the
   * elapsed interval into `globalIndex` under those old inputs. Returns the
   * cutoff — the last instant priced under the old regime, which is also where
   * the next interval begins because `_loadContext(true)` leaves
   * `globalIndex.timestamp` there.
   *
   * This deliberately reuses `_loadContext(true)`, the same checkpoint
   * `setFundingRate`, `setOffChainFundingRate`, and `delistPerpetual` already
   * perform, rather than adding a second index-advancing path. Its oracle
   * domain, round-integrity, future-dating, and staleness checks are what "old
   * inputs are still usable" means: when they fail the transition reverts, and
   * the owner must go through {emergencyStopTradingAtCutoff} with a reviewed
   * cutoff.
   *
   * Skipped while `tradingStartTime == 0`. No funding can accrue in that state
   * — `trade()` reverts 'P8' and a stopped funder reports a zero rate — and
   * the dependency addresses may still be unset during deployment wiring, so
   * forcing an oracle read there would brick initial configuration.
   *
   * On a DELISTED market this still advances `globalIndex`, which the
   * transitions did not do before. That is deliberate and is the point of the
   * fix: without it the whole settlement-quarantine window would later be
   * repriced at whatever rate the transition installed. Settlement itself is
   * unaffected — `closePosition` and friends read the frozen `delistIndex`
   * captured at delist time, never `globalIndex`.
   */
  function _checkpointFundingInputs() internal returns (uint128) {
    if (tradingStartTime == 0) {
      return globalIndex.timestamp;
    }
    return _loadContext(true).index.timestamp;
  }

  function _attemptBackstopInheritance(
    address account
  ) internal returns (bool) {
    if (backstopVault == address(0) || backstopTriggerMarginFractionE18 == 0) {
      return false;
    }

    Types.Context memory context = _loadContext(false);
    (
      Types.PositionBalance memory rawPosition,
      int256 localIndexValue
    ) = packedAccounts[account].load();
    // Settle pending funding IN MEMORY before the trigger check so the
    // equity evaluated here matches what a real settlement would produce
    // (and what the off-chain planner computes). Declined paths stay
    // read-only — callers treat this as a probe and most calls decline.
    Types.PositionBalance memory position = _settlePendingFunding(
      rawPosition,
      localIndexValue,
      context.index.value,
      context.price
    ).balance;
    if (position.qPos == 0) {
      return false;
    }

    int256 equity = _positionEquity(position, context.price);
    if (equity <= 0) {
      return false;
    }

    // Measure maintenance against the same risk notional the canonical margin
    // ratio divides by (PositionBalanceMath.getMarginRatioWithBinaryCheck), not
    // spot notional. For a binary short those diverge in opposite directions
    // near the upper payout bound: remaining payout exposure (qPos - qPos *
    // price) falls toward zero while spot notional rises toward the full
    // quantity. Using spot notional there inflates the trigger far above the
    // account's actual maintenance requirement and lets the vault inherit a
    // position the trading path still classifies as healthy. Longs and every
    // non-binary position keep spot notional, so their behavior is unchanged.
    uint128 riskNotional = PositionBalanceMath.getRiskNotional(
      position,
      context.price,
      _isBinaryFutureMarket()
    );
    uint128 maintenance = riskNotional.baseMul(
      SafeCast.toUint128(uint256(maintenanceMarginRequired))
    );
    uint128 trigger = maintenance.baseMul(backstopTriggerMarginFractionE18);
    if (uint256(equity) >= uint256(trigger)) {
      return false;
    }

    // Below this strict boundary, the position and its remaining isolated
    // margin transfer together. The resulting positive residual equity is the
    // backstop child's insurance fee for assuming tail risk, not a user refund.
    // Inheritance will be attempted: persist the settlement through the
    // canonical path FIRST so its events fire (AccountSettlementUpdate,
    // plus SettlementAmountNotPaidCompletely when margin and positive profit
    // cannot cover the debit). The transfer below re-baselines the account as
    // an empty position, which would otherwise consume the funding-index gap
    // silently — any write-off realized here would never reach off-chain
    // monitoring. On the in-trade probe path accounts are settled at trade
    // start, so this re-settle is a no-op there; if the vault declines below,
    // the settlement stands as correct maintenance either way.
    position = _applyFundRateToAccount(context, account);

    try
      IBackstopVault(backstopVault).inheritPosition(
        account,
        address(this),
        position
      )
    returns (bytes32 inheritanceId, address inheritingChild) {
      try
        this.completeBackstopInheritance(
          inheritanceId,
          account,
          inheritingChild,
          position,
          context,
          _msgSender()
        )
      returns (bool inherited) {
        return inherited;
      } catch (bytes memory reason) {
        emit BackstopInheritanceFailed(
          account,
          address(this),
          inheritingChild,
          position,
          reason
        );
        return false;
      }
    } catch (bytes memory reason) {
      emit BackstopInheritanceFailed(
        account,
        address(this),
        address(0),
        position,
        reason
      );
      return false;
    }
  }

  function _transferPositionToChildVault(
    bytes32 inheritanceId,
    address account,
    address inheritingChild,
    Types.PositionBalance memory inheritedPosition,
    Types.Context memory context,
    address sender
  ) internal returns (bool) {
    require(inheritingChild != address(0), 'P41');
    require(inheritingChild != account, 'P42');

    Types.PositionBalance memory childPosition = _applyFundRateToAccount(
      context,
      inheritingChild
    );
    Types.PositionBalance memory prevChildPosition = _copyPositionBalance(
      childPosition
    );
    Types.PositionBalance memory prevUserPosition = _copyPositionBalance(
      inheritedPosition
    );

    BackstopMergeResult memory mergeResult = _mergeInheritedPosition(
      childPosition,
      inheritedPosition,
      context.price
    );
    if (!mergeResult.success) {
      emit BackstopInheritanceFailed(
        account,
        address(this),
        inheritingChild,
        inheritedPosition,
        mergeResult.failureReason
      );
      return false;
    }

    if (mergeResult.childFreeCollateralDelta > 0) {
      IMarginBank(addresses.marginBank).transferMarginToAccount(
        address(this),
        inheritingChild,
        BaseMath.absolute(mergeResult.childFreeCollateralDelta)
      );
    } else if (mergeResult.childFreeCollateralDelta < 0) {
      IMarginBank(addresses.marginBank).transferMarginToAccount(
        inheritingChild,
        address(this),
        BaseMath.absolute(mergeResult.childFreeCollateralDelta)
      );
    }

    Types.PositionBalance memory emptyPosition = Types.PositionBalance({
      isPosPositive: false,
      mro: 0,
      qPos: 0,
      margin: 0,
      oiOpen: 0
    });

    packedAccounts[account].store(emptyPosition, context.index.value);
    packedAccounts[inheritingChild].store(
      mergeResult.childPosition,
      context.index.value
    );

    emit AccountPositionUpdate(
      account,
      sender,
      emptyPosition,
      prevUserPosition,
      Action.BACKSTOP_INHERIT,
      context.index.value,
      context.index.timestamp,
      -int256(uint256(prevUserPosition.margin))
    );

    emit AccountPositionUpdate(
      inheritingChild,
      sender,
      mergeResult.childPosition,
      prevChildPosition,
      Action.BACKSTOP_INHERIT,
      context.index.value,
      context.index.timestamp,
      int256(uint256(mergeResult.childPosition.margin)) -
        int256(uint256(prevChildPosition.margin))
    );

    emit BackstopInheritanceExecuted(
      inheritanceId,
      account,
      address(this),
      inheritingChild,
      context.price,
      inheritedPosition,
      mergeResult.childPosition,
      mergeResult.childFreeCollateralDelta
    );

    return true;
  }

  function _mergeInheritedPosition(
    Types.PositionBalance memory childPosition,
    Types.PositionBalance memory inheritedPosition,
    uint128 price
  ) internal pure returns (BackstopMergeResult memory result) {
    int256 totalEquity = _positionEquity(childPosition, price) +
      _positionEquity(inheritedPosition, price);
    Types.PositionBalance memory merged = childPosition;

    if (childPosition.qPos == 0) {
      merged.isPosPositive = inheritedPosition.isPosPositive;
      merged.qPos = inheritedPosition.qPos;
      merged.oiOpen = inheritedPosition.qPos.baseMul(price);
      merged.mro = inheritedPosition.mro;
    } else if (childPosition.isPosPositive == inheritedPosition.isPosPositive) {
      merged.qPos = childPosition.qPos + inheritedPosition.qPos;
      merged.oiOpen =
        childPosition.oiOpen +
        inheritedPosition.qPos.baseMul(price);
    } else if (childPosition.qPos > inheritedPosition.qPos) {
      merged.qPos = childPosition.qPos - inheritedPosition.qPos;
      merged.oiOpen = childPosition.oiOpen.baseMul(merged.qPos).baseDiv(
        childPosition.qPos
      );
    } else if (childPosition.qPos == inheritedPosition.qPos) {
      merged = Types.PositionBalance({
        isPosPositive: false,
        mro: 0,
        qPos: 0,
        margin: 0,
        oiOpen: 0
      });
      result.childPosition = merged;
      result.childFreeCollateralDelta = totalEquity;
      result.success = true;
      return result;
    } else {
      merged.isPosPositive = inheritedPosition.isPosPositive;
      merged.qPos = inheritedPosition.qPos - childPosition.qPos;
      merged.oiOpen = merged.qPos.baseMul(price);
      merged.mro = inheritedPosition.mro;
    }

    int256 pnl = _positionPnl(merged, price);
    int256 requiredMargin = totalEquity - pnl;
    if (requiredMargin < 0) {
      result.failureReason = abi.encodeWithSignature('Error(string)', 'P43');
      return result;
    }
    if (requiredMargin > int256(uint256(type(uint128).max))) {
      result.failureReason = abi.encodeWithSignature('Error(string)', 'P44');
      return result;
    }
    merged.margin = uint128(uint256(requiredMargin));
    result.childPosition = merged;
    result.childFreeCollateralDelta = 0;
    result.success = true;
  }

  function _positionEquity(
    Types.PositionBalance memory position,
    uint128 price
  ) internal pure returns (int256) {
    return int256(uint256(position.margin)) + _positionPnl(position, price);
  }

  function _positionPnl(
    Types.PositionBalance memory position,
    uint128 price
  ) internal pure returns (int256) {
    if (position.qPos == 0) {
      return 0;
    }
    int256 notional = int256(uint256(position.qPos.baseMul(price)));
    return
      position.isPosPositive
        ? notional - int256(uint256(position.oiOpen))
        : int256(uint256(position.oiOpen)) - notional;
  }

  function _positiveUnrealizedPnl(
    Types.PositionBalance memory position,
    uint128 price
  ) internal pure returns (uint128) {
    if (position.qPos == 0) {
      return 0;
    }

    uint128 notional = position.qPos.baseMul(price);
    if (position.isPosPositive) {
      return notional > position.oiOpen ? notional - position.oiOpen : 0;
    }
    return position.oiOpen > notional ? position.oiOpen - notional : 0;
  }

  /// Result of applying pending funding to a position balance.
  struct FundingSettlement {
    // Post-settlement balance (aliases the input memory struct).
    Types.PositionBalance balance;
    // False when indices were equal or the account has no position; no
    // settlement event should be emitted in that case.
    bool applied;
    // True when funding was owed TO the account (margin credited).
    bool isCredit;
    // Funding amount from the index formula: floor for credits, ceil for debits.
    uint128 formulaAmount;
    // Amount applied to margin: credited for credits, collected for debits.
    uint128 marginPortion;
    // Debit portion collected from positive unrealized profit by moving oiOpen
    // toward current oracle notional.
    uint128 profitPortion;
    // Debit portion margin and positive unrealized profit could not cover.
    // Written off — emitted as SettlementAmountNotPaidCompletely by the
    // persisting path so off-chain monitoring can sum it.
    uint128 forgiven;
  }

  /**
   * @dev Single source of truth for funding-settlement math, shared by the
   * persisting path (_applyFundRateToAccount) and the view paths
   * (accountFundingAdjustedEquity, which LiquidityVault.totalNAV depends on
   * for LP share pricing, and isAccountAdlEligible).
   *
   * Settlement collects in this order: credits add to margin; debits subtract
   * from margin first, then collect from positive unrealized profit by moving
   * oiOpen toward current oracle notional, then forgive only the remainder.
   *
   * Settlement does not revert on a funding shortfall, so funding-shortfall
   * accounts can still be traded against, liquidated, closed, and topped up.
   *
   * Mutates and returns the input `balance` (memory structs alias).
   * Credits round down and debits round up to avoid capital leakage.
   */
  function _settlePendingFunding(
    Types.PositionBalance memory balance,
    int256 oldIndexValue,
    int256 newIndexValue,
    uint128 oraclePrice
  ) internal pure returns (FundingSettlement memory result) {
    result.balance = balance;
    if (oldIndexValue == newIndexValue || balance.qPos == 0) {
      return result;
    }
    result.applied = true;

    // Considering position direction, compute the correct difference between indices
    int256 indexDiff = balance.isPosPositive
      ? oldIndexValue - newIndexValue // for long: local - global
      : newIndexValue - oldIndexValue; // for short: global - local

    if (indexDiff > 0) {
      result.isCredit = true;
      result.formulaAmount = indexDiff.absolute().baseMul(balance.qPos);
      result.marginPortion = result.formulaAmount;
      balance.margin += result.marginPortion;
      return result;
    }

    result.formulaAmount = indexDiff.absolute().baseMulRoundUp(balance.qPos);
    result.marginPortion = BaseMath.min(balance.margin, result.formulaAmount);
    balance.margin -= result.marginPortion;

    uint128 remaining = result.formulaAmount - result.marginPortion;
    if (remaining == 0) {
      return result;
    }

    uint128 profitAvailable = _positiveUnrealizedPnl(balance, oraclePrice);
    result.profitPortion = BaseMath.min(remaining, profitAvailable);
    if (result.profitPortion > 0) {
      if (balance.isPosPositive) {
        balance.oiOpen += result.profitPortion;
      } else {
        balance.oiOpen -= result.profitPortion;
      }
      remaining -= result.profitPortion;
    }

    result.forgiven = remaining;
    return result;
  }

  /**
   * @dev Accumulates trade results for a single user in the batch
   * @param accumulators Array of per-user accumulators (indexed by account position)
   * @param accountIndex Index into accumulators array for this user
   * @param quantity Trade quantity
   * @param fee Fee for this side of the trade
   * @param pnl Realized PnL for this side
   * @param fundsFlow Margin flow for this side
   * @param marginDelta Position margin change for this side
   * @param price Trade price (uniform clearing price)
   * @param fillIsLong Whether THIS fill's side is long for this account
   */
  function _accumulateTradeResult(
    TraderAccumulator[] memory accumulators,
    uint128 accountIndex,
    uint128 quantity,
    uint128 fee,
    int256 pnl,
    int256 fundsFlow,
    int256 marginDelta,
    uint128 price,
    bool fillIsLong
  ) internal pure {
    TraderAccumulator memory acc = accumulators[accountIndex];
    acc.totalQuantity += quantity;
    acc.totalFee += fee;
    acc.totalPnl += pnl;
    acc.fundsFlow += fundsFlow;
    acc.marginDelta += marginDelta;
    acc.price = price; // Same for all trades in batch (uniform clearing price)
    // Deliberately first-fill-only: later fills, including ones on the opposite
    // side, do not revise it. See BatchTradeExecuted's NatSpec.
    if (!acc.hasActivity) {
      acc.firstFillIsLong = fillIsLong;
    }
    acc.hasActivity = true;
    accumulators[accountIndex] = acc;
  }

  /**
   * @dev returns the context contaning current oracle price, funding rate and global index
   * @param shouldUpdateGlobalIndex a boolean indicating if new global index is to be computed
   */
  function _loadContext(
    bool shouldUpdateGlobalIndex
  ) internal returns (Types.Context memory) {
    // load old index
    Types.Index memory index = globalIndex;

    // get Price (P)
    (
      uint80 roundId,
      int256 price,
      ,
      uint256 updatedAt,
      uint80 answeredInRound
    ) = IPriceOracle(addresses.oracle).latestRoundData();
    _requireSupportedOraclePrice(price);

    int256 fundingRate = IFundingOracle(addresses.funder).getFundingRate();

    if (shouldUpdateGlobalIndex) {
      uint128 currentTimestamp = _blockTimestamp();
      // Block time is already loaded on this branch, so the upper bound is
      // free here. This is the recurring re-check for a feed that installed
      // clean and degraded afterwards; the trade hot path relies on it,
      // because a NONZERO `maxBatchesPerGlobalIndexUpdate` forces trading back
      // through this branch. MNX's off-chain deployment tooling refuses to
      // launch a market at zero.
      _requireOracleRoundNotFutureDated(updatedAt, currentTimestamp);
      _requireFreshOracle(
        roundId,
        updatedAt,
        answeredInRound,
        currentTimestamp
      );
      _resetGlobalIndexBatchBudget(currentTimestamp);
      index = _applyFundingToGlobalIndex(
        index,
        fundingRate,
        price,
        currentTimestamp
      );
    } else {
      // The trade hot path intentionally checks freshness against the
      // cached global-index timestamp instead of the current block timestamp.
      // The off-chain engine rejects stale oracle batches before
      // submission; this contract-side check is the cached-time
      // backstop, while updateGlobalIndex and other non-hot paths can compare
      // against the current block timestamp.
      //
      // Note what this branch does NOT do: no future-dating check. That check
      // needs block time, and reading volatile block data here would drop the
      // whole trade batch to MegaETH's lower compute ceiling — the same
      // reason `trade()` derives `settlementTimestamp` from the cached index.
      // Round integrity below is `pure` and stays. The future-dating bound is
      // enforced where a bad feed enters (`_requireValidOracle`) and
      // re-checked every `updateGlobalIndex`, which a NONZERO
      // `maxBatchesPerGlobalIndexUpdate` forces trading back through.
      _requireFreshOracle(roundId, updatedAt, answeredInRound, index.timestamp);
    }

    return
      Types.Context({
        price: uint128(uint256(price)),
        fundingRate: fundingRate,
        index: index
      });
  }

  function _requireGlobalIndexBatchBudget() internal view {
    uint128 maxBatches = maxBatchesPerGlobalIndexUpdate;
    if (maxBatches == 0) {
      return;
    }
    require(batchesSinceGlobalIndexUpdate < maxBatches, 'P59');
  }

  function _consumeGlobalIndexBatchBudget() internal {
    uint128 maxBatches = maxBatchesPerGlobalIndexUpdate;
    if (maxBatches == 0) {
      return;
    }
    batchesSinceGlobalIndexUpdate += 1;
  }

  function _resetGlobalIndexBatchBudget(uint128 timestamp) internal {
    uint128 priorBatchCount = batchesSinceGlobalIndexUpdate;
    if (priorBatchCount == 0) {
      return;
    }
    batchesSinceGlobalIndexUpdate = 0;
    emit GlobalIndexBatchCountReset(priorBatchCount, timestamp);
  }

  function _loadDelistContextAtPrice(
    uint128 price
  ) internal view returns (Types.Context memory) {
    Types.Index memory index = globalIndex;
    int256 signedPrice = int256(uint256(price));
    int256 fundingRate = IFundingOracle(addresses.funder).getFundingRate();

    index = _computeFundingIndex(
      index,
      fundingRate,
      signedPrice,
      _blockTimestamp()
    );

    return
      Types.Context({price: price, fundingRate: fundingRate, index: index});
  }

  function _applyFundingToGlobalIndex(
    Types.Index memory index,
    int256 fundingRate,
    int256 price,
    uint128 currentTimestamp
  ) private returns (Types.Index memory) {
    uint128 previousTimestamp = index.timestamp;
    index = _computeFundingIndex(index, fundingRate, price, currentTimestamp);

    if (index.timestamp == previousTimestamp) {
      return index;
    }

    globalIndex = index;

    emit GlobalIndexUpdate(globalIndex.value, index.timestamp);

    return index;
  }

  function _computeFundingIndex(
    Types.Index memory index,
    int256 fundingRate,
    int256 price,
    uint128 currentTimestamp
  ) private pure returns (Types.Index memory) {
    uint128 timeDelta = currentTimestamp - index.timestamp;

    if (timeDelta == 0) {
      return index;
    }

    int256 fundingValue = (fundingRate * int256(uint256(timeDelta))).baseMul(
      price
    );

    // Update the index according to the funding rate, applied over the time delta.
    index.value = index.value + fundingValue;
    index.timestamp = currentTimestamp;

    return index;
  }

  function _setDelistCloseDelaySeconds(uint128 delaySeconds) private {
    require(delaySeconds > 0, 'P52');
    delistCloseDelaySeconds = delaySeconds;
  }

  function _requireDelistCloseDelayConfigured() private view {
    require(delistCloseDelaySeconds > 0, 'P52');
  }

  function _recordDelist(uint128 price, Types.Index memory index) private {
    _requireDelistCloseDelayConfigured();
    delistingPrice = price;
    delistIndex = index;
    delisted = true;
    delistedAt = _blockTimestamp();

    // Open a fresh audit #41 claim epoch for this delisting, so a re-delist at
    // a different settlement price can never pay a claim valued at an earlier
    // one.
    _resetDelistClaimState();

    emit PerpetualDelisted(delistingPrice);
  }

  /**
   * @dev Invalidates every audit #41 registration and zeroes the aggregates.
   * Called when a delisting begins and when one is aborted, so registration
   * state is only ever scoped to the delisting it was computed against.
   *
   * Per-account mapping entries are versioned rather than deleted: storage is
   * not enumerable, so there is no way to clear them, but bumping the epoch
   * makes every one of them stop matching in O(1).
   */
  function _resetDelistClaimState() private {
    delistEpoch += 1;
    registeredDelistClaimCount = 0;
    registeredDelistClaimTotalE18Raw = 0;
    outstandingDelistClaimE18Raw = 0;
    delistClaimRatioE18 = 0;
    delistClaimRatioLocked = false;
    delistClaimsFinalizedAt = 0;
    delistFallbackSettlementStarted = false;
  }

  function _loadDelistSettlementContext()
    private
    view
    returns (Types.Context memory)
  {
    return
      Types.Context({
        price: delistingPrice,
        fundingRate: 0,
        index: delistIndex
      });
  }

  /**
   * @dev Verify that `accounts` contains at least one address and that the contents are unique.
   *  We verify uniqueness by requiring that the array is sorted.
   */
  function _verifyAccounts(address[] memory accounts) private pure {
    require(accounts.length > 0, 'P31');

    // Require accounts to be unique and sorted
    address prevAccount = accounts[0];
    for (uint128 i = 1; i < accounts.length; i++) {
      address account = accounts[i];
      require(account > prevAccount, 'P32');
      prevAccount = account;
    }
  }

  /**
   * @dev Given a list of accounts, apply funding and return resulting balances
   */
  function _applyFundingRate(
    Types.Context memory context,
    address[] memory accounts
  ) internal returns (Types.PositionBalance[] memory) {
    uint256 numAccounts = accounts.length;

    Types.PositionBalance[] memory result = new Types.PositionBalance[](
      numAccounts
    );

    for (uint256 i = 0; i < numAccounts; i++) {
      result[i] = _applyFundRateToAccount(context, accounts[i]);
    }

    return result;
  }

  /**
   * @dev Given a single account, apply funding via _settlePendingFunding
   * and persist the resulting balance.
   */
  function _applyFundRateToAccount(
    Types.Context memory context,
    address account
  ) internal returns (Types.PositionBalance memory) {
    int256 newIndexValue = context.index.value;

    (
      Types.PositionBalance memory balance,
      int256 oldIndexValue
    ) = packedAccounts[account].load();

    FundingSettlement memory settlement = _settlePendingFunding(
      balance,
      oldIndexValue,
      newIndexValue,
      context.price
    );
    // If index value unchanged or no position, no settlement needed
    if (!settlement.applied) {
      // Deliberately leave no-op settlements unwritten. This entrypoint is
      // public, so re-baselining flat accounts would let anyone create
      // persistent packed-account slots for arbitrary addresses. Flat-account
      // funding indexes are dead values: every position-opening path stamps
      // the stored balance with the current global index.
      return settlement.balance;
    }

    if (settlement.forgiven > 0) {
      // The account's margin plus positive unrealized profit could not cover
      // this much of the debit. It is written off; the event is the
      // measurement that off-chain monitoring can sum and alert on.
      emit SettlementAmountNotPaidCompletely(account, settlement.forgiven);
    }

    packedAccounts[account].store(settlement.balance, newIndexValue);

    emit AccountSettlementUpdate(
      account,
      settlement.balance,
      settlement.isCredit,
      settlement.formulaAmount,
      settlement.marginPortion,
      settlement.profitPortion,
      settlement.forgiven,
      newIndexValue,
      context.price,
      context.fundingRate,
      context.index.timestamp
    );

    return settlement.balance;
  }

  function _verifyAccountState(
    Types.Context memory context,
    address[] memory accounts,
    Types.PositionBalance[] memory initialPositionBalances,
    bytes32 traderFlags,
    bool[] memory liquidationMarginBypass,
    bool[] memory onlySameSideReductions
  ) private view {
    for (uint128 i = 0; i < accounts.length; i++) {
      Types.PositionBalance memory initialBalance = initialPositionBalances[i];

      _verifyMarginRatioForAccount(
        accounts[i],
        initialBalance,
        context.price,
        traderFlags,
        liquidationMarginBypass[i],
        onlySameSideReductions[i]
      );
    }
  }

  function _verifyMarginRatioForAccount(
    address account,
    Types.PositionBalance memory initialBalance,
    uint128 price,
    bytes32 traderFlags,
    bool liquidationMarginBypass,
    bool onlySameSideReductions
  ) internal view {
    (Types.PositionBalance memory currentBalance, ) = packedAccounts[account]
      .load();

    // Check if this is a binary future market (for the 1x and binary-short margin rules)
    bool isBinaryMarket = _isBinaryFutureMarket();

    int256 oldMarginRatio = PositionBalanceMath.getMarginRatioWithBinaryCheck(
      initialBalance,
      price,
      isBinaryMarket
    );
    int256 curMarginRatio = PositionBalanceMath.getMarginRatioWithBinaryCheck(
      currentBalance,
      price,
      isBinaryMarket
    );

    bool isNewOrFlip = initialBalance.qPos == 0 ||
      currentBalance.isPosPositive != initialBalance.isPosPositive;
    bool isSameSideRiskReducing = currentBalance.qPos < initialBalance.qPos &&
      currentBalance.isPosPositive == initialBalance.isPosPositive;

    if (
      isNewOrFlip &&
      isBinaryMarket &&
      PositionBalanceMath.isOneXPosition(currentBalance)
    ) {
      Require.that(
        PositionBalanceMath.hasBinaryMaxLossCollateralFloor(currentBalance),
        'P34',
        account
      );
      Require.that(curMarginRatio >= maintenanceMarginRequired, 'P34', account);
      return;
    }

    // Case 0: Current Margin Ratio >= IMR: User can increase and reduce positions.
    if (curMarginRatio >= initialMarginRequired) {
      return;
    }

    // P34: New/flip measures margin against entry exposure (oiOpen, or
    // qPos - oiOpen for a binary short)
    //
    // A new position and a flip are both fresh exposure, so they carry the
    // full initial-margin requirement measured at their own entry price:
    // `margin >= ceil(entryExposure * initialMarginRequired)`, which is
    // exactly `leverage <= 1 / initialMarginRequired` for the opening margin
    // `IsolatedTrader` computes. The entry basis (rather than the oracle
    // basis of Case 0) is what keeps max-leverage market orders executable
    // when the clearing price differs from the oracle by a tick; the
    // additional maintenance-margin floor below stops an entry so far from
    // the oracle that the position would be born liquidatable.
    if (isNewOrFlip) {
      uint128 requiredMargin = _getEntryMarginRequirementForP34(
        currentBalance,
        isBinaryMarket
      );
      Require.that(currentBalance.margin >= requiredMargin, 'P34', account);
      Require.that(curMarginRatio >= maintenanceMarginRequired, 'P34', account);
      return;
    }

    // A fully margined add (see `_isFullyMarginedAdd`) is judged like the
    // one-batch fill it would otherwise have been: it may lower the ratio
    // (Case II) and grow while under IMR (Case V). Case III still requires the
    // whole position to end above maintenance margin.
    bool fullyMarginedAdd = _isFullyMarginedAdd(
      initialBalance,
      currentBalance,
      oldMarginRatio,
      traderFlags,
      liquidationMarginBypass,
      isBinaryMarket
    );

    // Case II: For MR < IMR: require MR to have improved or stayed the same.
    // Pure same-side reductions are allowed through because closing size
    // reduces exposure; the batch-level flag prevents close-then-add batches
    // from using the same exception.
    if (
      !fullyMarginedAdd && !(onlySameSideReductions && isSameSideRiskReducing)
    ) {
      Require.that(curMarginRatio >= oldMarginRatio, 'P35', account);
    }

    // Case III: For MR <= MMR require qPos to go down or stay the same
    Require.that(
      curMarginRatio > maintenanceMarginRequired ||
        (initialBalance.qPos >= currentBalance.qPos &&
          initialBalance.isPosPositive == currentBalance.isPosPositive),
      'P36',
      account
    );

    // Case IV: For MR < 0 require a forced exit: this account was a forced side
    // of a book-liquidation fill (`liquidationMarginBypass`), or the batch is
    // ADL, which exempts every account in it (`traderFlags == ADL_TRADER_FLAG`).
    // @dev IsolatedTrader batches use flag 1, with per-fill flags 2 and 4 for
    // book liquidations inside them; IsolatedADL batches use flag 3. trade()
    // rejects any other batch flag with 'P12'.
    Require.that(
      curMarginRatio >= 0 ||
        liquidationMarginBypass ||
        traderFlags == ADL_TRADER_FLAG,
      'P37',
      account
    );

    // Case V: an existing position under the initial-margin requirement may
    // only be de-risked. Growing absolute quantity, flipping side, or
    // selecting higher leverage (a lower stored `mro`) is a risk increase and
    // has to satisfy the full initial-margin requirement — which Case 0 above
    // already returned for. Reaching here means the final oracle-basis ratio
    // is still under it, so the increase is rejected: holding an
    // under-margined ratio flat is not "no worse", it is the same inadequate
    // margin backing more exposure.
    //
    // This sits last on purpose. Cases II-IV keep their existing revert codes
    // for every transition they already rejected; P68 only fires where those
    // three used to let a risk increase through, namely an under-margined
    // account whose ratio held or improved while its exposure grew.
    //
    // Liquidation, forced liquidation, automatic deleveraging, and reduce-only
    // exits all shrink the distressed account's quantity, so the classifier
    // reports no risk increase and this check is transparent to them.
    //
    // The one exception is a fully margined add: its new exposure carries its
    // own initial margin, the account started above maintenance margin, and
    // Case III kept it there.
    Require.that(
      fullyMarginedAdd ||
        !PositionBalanceMath.isRiskIncreasingTransition(
          initialBalance,
          currentBalance
        ),
      'P68',
      account
    );
  }

  /**
   * @dev True for an ordinary order fill (a normal-flag batch, which is also
   * where book liquidations settle) that grows a same-side position at an
   * unchanged margin requirement, on an account that is not being liquidated
   * and was above maintenance margin before the trade, where the exposure it
   * adds brings its own initial margin at entry: P34's entry test applied to
   * the increment. Funding is settled before `initialBalance` is recorded, so
   * the margin difference is the trade's own. Any other shape, including a
   * settlement that reduces and then re-adds, is judged on its net change and
   * falls back to the strict rule when the net increment is under-margined.
   */
  function _isFullyMarginedAdd(
    Types.PositionBalance memory initialBalance,
    Types.PositionBalance memory currentBalance,
    int256 oldMarginRatio,
    bytes32 traderFlags,
    bool liquidationMarginBypass,
    bool isBinaryMarket
  ) internal view returns (bool) {
    if (
      traderFlags != NORMAL_TRADER_FLAG ||
      liquidationMarginBypass ||
      oldMarginRatio <= maintenanceMarginRequired ||
      initialBalance.qPos == 0 ||
      currentBalance.qPos <= initialBalance.qPos ||
      currentBalance.isPosPositive != initialBalance.isPosPositive ||
      currentBalance.mro != initialBalance.mro ||
      currentBalance.margin < initialBalance.margin
    ) {
      return false;
    }

    uint128 exposureBefore = _getEntryExposure(initialBalance, isBinaryMarket);
    uint128 exposureAfter = _getEntryExposure(currentBalance, isBinaryMarket);
    if (exposureAfter <= exposureBefore) {
      return false;
    }

    return
      currentBalance.margin - initialBalance.margin >=
      (exposureAfter - exposureBefore).baseMulRoundUp(
        SafeCast.toUint128(uint256(initialMarginRequired))
      );
  }

  function _copyPositionBalance(
    Types.PositionBalance memory balance
  ) internal pure returns (Types.PositionBalance memory) {
    return
      Types.PositionBalance({
        isPosPositive: balance.isPosPositive,
        mro: balance.mro,
        qPos: balance.qPos,
        margin: balance.margin,
        oiOpen: balance.oiOpen
      });
  }

  function _isSameSideReduction(
    Types.PositionBalance memory beforeBalance,
    Types.PositionBalance memory afterBalance
  ) internal pure returns (bool) {
    return
      beforeBalance.qPos > 0 &&
      afterBalance.qPos < beforeBalance.qPos &&
      (afterBalance.qPos == 0 ||
        afterBalance.isPosPositive == beforeBalance.isPosPositive);
  }

  function _getTargetMargin(
    Types.PositionBalance memory positionBalance,
    uint128 leverage,
    uint128 oraclePrice
  ) internal view returns (uint128) {
    if (_isBinaryFutureMarket() && !positionBalance.isPosPositive) {
      return
        PositionBalanceMath
          .computeBinaryShortCollateralFloor(positionBalance)
          .baseDivRoundUp(leverage);
    }

    return
      IMarginMath(addresses.marginMath).getTargetMargin(
        positionBalance,
        leverage,
        oraclePrice
      );
  }

  function _getBinaryShortMaxRemovableMargin(
    Types.PositionBalance memory positionBalance
  ) internal pure returns (uint128) {
    uint128 requiredMargin = PositionBalanceMath
      .computeBinaryShortCollateralFloor(positionBalance)
      .baseMul(positionBalance.mro);

    return
      positionBalance.margin > requiredMargin
        ? positionBalance.margin - requiredMargin
        : 0;
  }

  function _getEntryMarginRequirementForP34(
    Types.PositionBalance memory positionBalance,
    bool isBinaryMarket
  ) internal view returns (uint128) {
    return
      _getEntryExposure(positionBalance, isBinaryMarket).baseMulRoundUp(
        SafeCast.toUint128(uint256(initialMarginRequired))
      );
  }

  /**
   * @dev The exposure an opening fill's margin is sized on
   * (`IsolatedTrader._getOpeningMarginAmount`): entry notional, or max loss
   * (qPos - oiOpen) for a binary short.
   */
  function _getEntryExposure(
    Types.PositionBalance memory positionBalance,
    bool isBinaryMarket
  ) internal pure returns (uint128) {
    return
      isBinaryMarket && !positionBalance.isPosPositive
        ? PositionBalanceMath.computeBinaryShortCollateralFloor(positionBalance)
        : positionBalance.oiOpen;
  }
}
