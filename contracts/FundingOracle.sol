// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

// utils
import {Ownable2StepUpgradeable} from '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {BlockContext} from './utils/BlockContext.sol';

// interfaces
import {IFundingOracle} from './interfaces/IFundingOracle.sol';

// libraries
import {Types} from './libraries/Types.sol';

/**
 * @title Funding Oracle
 * @author MNX Markets <help@mnx.fi>
 * @notice Holds the per-second funding rate Perpetual applies to open
 * positions. An installed rate does not expire: it stays in force until the
 * next install, a funding-mode change, or {stopFunding}.
 * @dev Audit #75/#90: this contract no longer computes the
 * rate. Trade observation and premium accumulation were removed because they
 * never bound the operator — the exchange submits the trades, so a wash pair
 * steered the accumulator as freely as a submitted number would. The exchange
 * now computes the rate off-chain from the order book and installs it. What
 * this contract still guarantees is {maxFunding}, one ordinary install per
 * nominal window plus one replacement after each funding-mode transition, and
 * the funder lifecycle.
 * @dev The contract is made upgradable using openzeppelin upgrades-pluging, don't change
 * the order of variables. Read more: https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies
 */
contract FundingOracle is
  IFundingOracle,
  Ownable2StepUpgradeable,
  ReentrancyGuard,
  BlockContext
{
  //
  // EVENTS
  //

  /// @notice Emitted when funding rate provider is set, carrying the exact
  /// previous and new values so a rotation can be audited from logs alone.
  event FRProviderUpdate(
    address indexed previousProvider,
    address indexed newProvider
  );

  /// @notice Emitted when this oracle confirms its pairing with the Perpetual
  /// it names as provider, completing a funder handover.
  event ProviderPairingConfirmed(address indexed provider);

  /// @notice Emitted when Guardian changes how funding is computed.
  /// @dev `remainingWindowSeconds` is the part of the current nominal window
  /// still unpriced at `cutoffTimestamp`: the most of that window the one
  /// replacement rate permitted under `transitionNonce` can cover. Zero when
  /// funding has not started. No rate can be installed then or during the
  /// first window, so a transition there permits no replacement.
  event FundingModeTransition(
    bool onChainAllowed,
    uint64 transitionNonce,
    uint128 cutoffTimestamp,
    uint128 remainingWindowSeconds
  );

  /// @notice Emitted when a mode transition's one-shot allowance is consumed.
  /// @dev Fires on both consuming paths: an install that replaces the rate
  /// already set for that window, and — since the audit #76 closure — the
  /// window's first ordinary install when the transition landed before it.
  event FundingModeReplacementApplied(
    uint64 transitionNonce,
    uint128 window,
    uint128 cutoffTimestamp
  );

  /// @notice emitted when maxFunding allowed per hour/window updates
  event MaxAllowedFRUpdate(uint128 maxFunding);

  /// @notice Emitted when the guardian contract is set or rotated. Carries the
  /// exact previous and new values so a rotation can be audited from logs
  /// alone. On a fresh initialization the previous value is the zero address.
  event GuardianContractUpdate(
    address indexed previousGuardianContract,
    address indexed newGuardianContract
  );

  event FundingDecayHoursUpdate(uint128 fundingDecayHours);

  /// @notice Emitted when binary-market funding is permanently locked off.
  event BinaryMarketFundingLocked();

  /// @notice Emitted when funding rate start time is set
  event FundingRateStart(uint128 timestamp);

  /// @notice Emitted when funding rate is stopped
  event FundingRateStop(uint128 timestamp);

  /// @notice Emitted when funding rate is set
  /// @dev `remainingApplicationSeconds` is a DURATION in seconds, not a Unix
  /// timestamp: it is `nextWindowBoundary - timestamp`. The rate normally
  /// applies until that boundary, and longer if the next update stalls past
  /// it, but a funding-mode change or {stopFunding} zeroes it sooner.
  /// Indexers must not treat it as an absolute time.
  event FundingRateUpdate(
    int256 fundingRate, // per second funding rate
    uint128 window,
    uint128 remainingApplicationSeconds, // seconds left until the next funding window boundary
    uint128 timestamp
  );

  //
  // STRUCTS
  //

  /// @notice Deprecated. Held for storage layout only.
  /// @dev These fields fed the removed on-chain premium accumulation. No
  /// funding math reads them. They are still written by the lifecycle
  /// functions ({startFunding}, {stopFunding}, {setFundingRateStatus}), whose
  /// zeroing is what {confirmProviderPairing} checks to decide a funder's
  /// schedule is clean enough to adopt.
  struct FundingWindow {
    uint128 tFirst; // timestamp at which first record was updated
    uint128 tLast; // timestamp at which last record was updated
    int256 sum;
    int256 ratio;
  }

  //**********************************************************//
  //    The below state variables can not change the order    //
  //**********************************************************//

  //
  // CONSTANTS & VARIABLES
  //

  /// @notice Funding rate window has a fixed one-hour size.
  /// @dev Submitted per-window rates are stored per second using signed integer
  /// division by this value. Any nonzero rate with absolute value below 3600
  /// truncates to zero, so tests intending to prove a nonzero installation must
  /// use a seed whose absolute value is at least one full window.
  uint128 public constant FUNDING_RATE_WINDOW = 1 hours;

  /// @notice max funding rate allowed per hour
  /// @dev set from the `_maxFunding` initialize argument and owner-adjustable
  /// via {setMaxAllowedFundingRate}; a binary market must hold it at zero
  /// ({lockBinaryMarketFunding}; Perpetual reverts 'P65' otherwise)
  uint128 public maxFunding;

  /// @notice address allowed to install the funding rate (in either mode), to
  /// start and stop funding, and to confirm a funder handover
  /// @dev this will be the perpetual contract address, which relays the rate
  /// submitted by its `offchainFROperator`
  address public provider;

  /// @notice address of the guardian contract
  address public guardianContract;

  /// @notice timestamp at which funding rate was started
  uint128 public fundingStart;

  /// @notice current window for which funding rate is calculated and is to be applied
  /// @dev idealy this will update every hour, but can fall behind
  uint128 public windowSet;

  /// @notice current funding rate (per second) applied to open positions
  int256 public currentFundingRate;

  /// @notice Deprecated. See {FundingWindow}.
  FundingWindow public currentFundingWindow;

  /// @notice status of the funding rate as set by the Guardian
  Types.GuardianStatus private fundingRateStatus;

  uint256[50] private __gap;

  //**********************************************************//
  //    The above state variables can not change the order    //
  //**********************************************************//

  //◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤ add state variables below ◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤//

  /// @notice One-way lock for binary markets, which must keep maxFunding at zero.
  bool public binaryMarketFundingLocked;

  /// @notice Hours the funding premium is spread over — the per-market decay
  /// divisor of the off-chain rate computation.
  /// @dev The on-chain calculation that originally consumed this was removed
  /// (audit #75/#90), but the value is live, not residue: the exchange reads
  /// it from this contract before each install and divides the dead-banded
  /// premium by it, falling back to 24 only when it reads zero (legacy
  /// proxies). H100 configures 168. Owner-set via {setFundingDecayHours}.
  uint128 public fundingDecayHours;

  /// @notice Increments on every change to how funding is computed (on-chain
  /// vs off-chain). Identifies the single replacement rate permitted for the
  /// remainder of the window that change landed in.
  uint64 public fundingModeTransitionNonce;

  /// @notice The transition nonce whose one replacement has been used. Equal
  /// to `fundingModeTransitionNonce` once that replacement is installed, which
  /// is what makes ordinary duplicate updates stay rejected.
  uint64 public fundingModeReplacementUsedNonce;

  /// @notice Block time at which the most recent mode change took effect. The
  /// replacement applies only from here forward.
  uint128 public fundingModeTransitionAt;

  //◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣ add state variables above ◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣//

  modifier onlyFundingRateProvider() {
    require(
      provider == _msgSender(),
      'FundingOracle: caller is not funding rate provider'
    );
    _;
  }

  /**
   * Throws if called by any account other than the guardian
   */
  modifier onlyGuardianContract() {
    require(
      guardianContract == _msgSender(),
      'FundingOracle: caller is not the guardian contract'
    );
    _;
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  /**
   * @notice initializes the contract
   * @param _provider address of the funding rate provider. The zero address
   * is expected here: the Perpetual that will be the provider does not exist
   * yet at this point in the deploy, and {setFundingRateProvider} wires it
   * afterwards.
   * @param _guardian address of guardian contract. Validated: see
   * {_setGuardianContract}.
   */
  function initialize(
    address _provider,
    address _guardian,
    uint128 _maxFunding
  ) public initializer {
    provider = _provider;
    _setGuardianContract(_guardian);
    maxFunding = _maxFunding;
    fundingDecayHours = 24;

    __Ownable_init(_msgSender());
    __Ownable2Step_init();

    emit FRProviderUpdate(address(0), provider);
    emit MaxAllowedFRUpdate(maxFunding);
    emit FundingDecayHoursUpdate(fundingDecayHours);
  }

  //===========================================================//
  //                         SETTERS
  //===========================================================//

  /**
   * @notice Installs the rate for the current window while the off-chain
   * funding mode is active.
   * @dev The mode gate is the only thing separating this from
   * {setFundingRate}; see {_installFundingRate} for the shared semantics.
   * @param _offchainFundingRate the rate for one whole funding window
   */
  function setOffChainFundingRate(
    int256 _offchainFundingRate
  ) public override onlyFundingRateProvider nonReentrant {
    require(
      !isFundingRateAllowed(),
      'FundingOracle: off-chain funding rate cannot be set while on-chain allowed'
    );

    _installFundingRate(_offchainFundingRate);
  }

  /**
   * @notice Installs the rate for the current window while on-chain funding
   * is the allowed mode.
   * @dev Audit #75/#90: this contract no longer derives the
   * rate. The exchange computes it off-chain from the order book and submits
   * it here; the honest on-chain guarantees are {maxFunding}, one ordinary
   * install per nominal window plus one replacement after each funding-mode
   * transition, and the funder lifecycle. See {_installFundingRate}.
   * @param _fundingRate the rate for one whole funding window
   */
  function setFundingRate(
    int256 _fundingRate
  ) public override onlyFundingRateProvider nonReentrant {
    require(
      isFundingRateAllowed(),
      'FundingOracle: on-chain funding rate cannot be applied at the moment'
    );

    _installFundingRate(_fundingRate);
  }

  /**
   * @notice Updates funding rate status of this market
   * @dev Must be called by the Guardian
   * @param _newStatus status of funding rate for this market. ALLOWED selects
   * the on-chain mode ({setFundingRate}); any other status selects the
   * off-chain mode ({setOffChainFundingRate}). The rate is supplied off-chain
   * in both modes.
   */
  function setFundingRateStatus(
    Types.GuardianStatus _newStatus
  ) external override nonReentrant onlyGuardianContract {
    bool wasAllowed = isFundingRateAllowed();
    bool nowAllowed = _newStatus == Types.GuardianStatus.ALLOWED;
    fundingRateStatus = _newStatus;

    // A restatement of the current mode changes nothing — in particular it
    // must not reset the funding window or arm a replacement.
    if (wasAllowed == nowAllowed) {
      return;
    }

    // Both directions of this transition zero the rate for the rest of the
    // current window, so both arm the one replacement that repairs it.
    _recordFundingModeTransition(nowAllowed);

    if (!nowAllowed) {
      currentFundingRate = 0;
      return;
    }

    // Moving funding rate back on-chain: discard the off-chain rate after
    // Guardian has allowed Perpetual to settle it into the global index.
    //
    // The window fields are reset here for the lifecycle's sake — it is what
    // {confirmProviderPairing} reads as a clean schedule — not for any
    // computation. Nothing derives a rate from them since audit #75/#90; the
    // replacement rate the #76 allowance permits is submitted, so it covers
    // the remainder of the window at whatever value the exchange computed
    // off-chain, with no partial-sample dilution to account for.
    uint128 currentTimestamp = _blockTimestamp();
    uint128 expectedWindow = _expectedFundingWindowAt(currentTimestamp);
    currentFundingRate = 0;
    windowSet = expectedWindow == 0 ? 0 : expectedWindow - 1;
    // Funding has not started; preserve startFunding's future window anchor.
    if (expectedWindow == 0) return;

    currentFundingWindow = FundingWindow({
      tFirst: currentTimestamp,
      tLast: currentTimestamp,
      ratio: 0,
      sum: 0
    });
  }

  /**
   * @notice Starts funding oracle's 1st window at specified time
   * @dev can only be invoked by funding rate provided i.e. perpetual
   * when trading is started on perpetual by admin using `startTrading`
   * the funding on funding oracle is started as well
   * @param _timestamp time at which funding will start
   */
  function startFunding(
    uint128 _timestamp
  ) public override onlyFundingRateProvider {
    require(fundingStart == 0, 'FundingOracle: Funding is already started');
    require(
      _timestamp > _blockTimestamp(),
      'FundingOracle: Start time must be > current block time'
    );

    fundingStart = _timestamp;

    currentFundingWindow.tFirst = _timestamp;
    currentFundingWindow.tLast = _timestamp;

    emit FundingRateStart(fundingStart);
  }

  /**
   * @notice Stops funding oracle
   * @dev can only be invoked by funding rate provided i.e. perpetual
   * when trading is stopped on perpetual by admin using `stopTrading`
   * the funding on funding oracle is stopped as well
   */
  function stopFunding() public override onlyFundingRateProvider {
    fundingStart = 0;

    // reset current funding rate to 0
    currentFundingRate = 0;

    windowSet = 0;

    // since funding has been stopped, reset current funding window
    currentFundingWindow = FundingWindow({
      tFirst: 0,
      tLast: 0,
      ratio: 0,
      sum: 0
    });

    // Disarm any pending mode-transition replacement: it belongs to a window
    // of a schedule that no longer exists. The nonce itself keeps counting so
    // it stays a stable correlation id across a stop/start.
    fundingModeReplacementUsedNonce = fundingModeTransitionNonce;
    fundingModeTransitionAt = 0;

    emit FundingRateStop(_blockTimestamp());
  }

  /**
   * @notice The funder's half of a two-sided funder handover.
   * @dev `onlyFundingRateProvider` IS the confirmation: only the Perpetual this
   * oracle already names as its provider can complete the call, so a handover
   * cannot be finished from the Perpetual's side alone. Perpetual invokes this
   * inside {Perpetual-setFunder}, which separately checks `provider()` before
   * calling; the two checks meet in the same transaction and neither contract
   * has to trust the other's view of the pairing.
   *
   * The schedule checks live here rather than in Perpetual because this is the
   * contract that owns the state — exporting four getters so a caller could
   * re-derive "clean" would put the definition in two places. Clean means
   * never started, or properly stopped: {stopFunding} zeroes exactly these
   * fields, so a funder retired from one market can be adopted by another.
   * A funder still carrying a live window is rejected rather than having its
   * start time, window, and rate silently imported into the new market.
   *
   * State-changing rather than a view so the acknowledgement is recorded on
   * this side of the pairing too.
   */
  function confirmProviderPairing()
    external
    override
    onlyFundingRateProvider
  {
    require(
      fundingStart == 0 && windowSet == 0 && currentFundingRate == 0,
      'FundingOracle: funding schedule is not clean'
    );
    require(
      currentFundingWindow.tFirst == 0 &&
        currentFundingWindow.tLast == 0 &&
        currentFundingWindow.sum == 0 &&
        currentFundingWindow.ratio == 0,
      'FundingOracle: funding window is not clean'
    );
    emit ProviderPairingConfirmed(_msgSender());
  }

  /**
   * @notice updates address of funding rate provider
   * @dev Validated, unlike the zero address {initialize} deliberately accepts:
   * by the time this setter is reachable the Perpetual exists, and the states
   * a bad value produces are severe. A provider with no code strands the
   * oracle — `startFunding`, `stopFunding`, and both install paths gate on it,
   * and Guardian's funding-status path refuses to zero a live rate through a
   * non-contract provider. Emits both addresses so a rotation is auditable
   * from logs alone.
   * @param _provider the new provider address
   */
  function setFundingRateProvider(address _provider) public onlyOwner {
    require(_provider != address(0), 'FundingOracle: invalid provider');
    require(
      _provider.code.length > 0,
      'FundingOracle: provider is not a contract'
    );
    address previousProvider = provider;
    provider = _provider;
    emit FRProviderUpdate(previousProvider, _provider);
  }

  /**
   * @notice Disabled. This oracle must always have an owner.
   * @dev Renouncing would freeze `provider`, `guardianContract`, `maxFunding`,
   * and `fundingDecayHours` forever. A market whose funder is misconfigured
   * could then only be repaired by replacing the funder outright, and a binary
   * market's funding lock could never be established. Ownership still moves
   * normally through `transferOwnership` / `acceptOwnership`.
   */
  function renounceOwnership() public pure override {
    revert('FundingOracle: ownership cannot be renounced');
  }

  /**
   * @notice Rotates the Guardian contract allowed to set funding status.
   * @dev A recovery and lifecycle operation, not a required release write: a
   * proxy whose guardian is already correct needs no call here. It exists
   * because {setFundingRateStatus} is gated solely on `guardianContract`, so
   * without a setter a wrong or unreachable value could only be repaired by a
   * proxy upgrade — unlike `provider` and `maxFunding`, which the owner can
   * already correct.
   * @param _guardian the replacement Guardian contract
   */
  function setGuardianContract(address _guardian) public onlyOwner {
    _setGuardianContract(_guardian);
  }

  /**
   * @dev Validates and stores the guardian, emitting the exact previous and
   * new values. Two separate checks on purpose: the zero address is the
   * likely misconfiguration and gets its own message, matching MarginBank's
   * `invalid guardian`.
   *
   * The role is expected to be a Guardian contract, so an address with no
   * deployed code is rejected. Guardian keeps no funding-oracle registry, so
   * there is nothing a replacement could attest back; code existence, the
   * owner gate, and {GuardianContractUpdate} are the whole control.
   */
  function _setGuardianContract(address _guardian) private {
    require(_guardian != address(0), 'FundingOracle: invalid guardian');
    require(
      _guardian.code.length > 0,
      'FundingOracle: guardian is not a contract'
    );
    address previousGuardianContract = guardianContract;
    guardianContract = _guardian;
    emit GuardianContractUpdate(previousGuardianContract, _guardian);
  }

  /**
   * @notice updates max allowed funding to the one provided
   * @param _maxFunding the new maximum funding rate per window
   */
  function setMaxAllowedFundingRate(uint128 _maxFunding) public onlyOwner {
    require(
      !binaryMarketFundingLocked || _maxFunding == 0,
      'FundingOracle: binary funding locked'
    );
    maxFunding = _maxFunding;
    emit MaxAllowedFRUpdate(maxFunding);
  }

  function setFundingDecayHours(uint128 _fundingDecayHours) public onlyOwner {
    require(
      1 <= _fundingDecayHours && _fundingDecayHours <= 8760,
      'FundingOracle: invalid funding decay hours'
    );
    fundingDecayHours = _fundingDecayHours;
    emit FundingDecayHoursUpdate(fundingDecayHours);
  }

  /**
   * @notice Permanently keeps max funding at zero for a binary market.
   * @dev Existing markets call this once during their upgrade campaign; new
   * binary deployments call it during deploy setup.
   */
  function lockBinaryMarketFunding() public onlyOwner {
    require(
      !binaryMarketFundingLocked,
      'FundingOracle: binary funding already locked'
    );
    require(maxFunding == 0, 'FundingOracle: max funding must be zero');
    require(
      currentFundingRate == 0,
      'FundingOracle: current funding rate must be zero'
    );
    binaryMarketFundingLocked = true;
    emit BinaryMarketFundingLocked();
  }

  //===========================================================//
  //                      GETTERS
  //===========================================================//

  /**
   * @notice returns current funding rate
   */
  function getFundingRate() external view override returns (int256) {
    return (currentFundingRate);
  }

  /**
   * Returns true while the on-chain funding mode (status ALLOWED) is active.
   */
  function isFundingRateAllowed() public view override returns (bool) {
    return fundingRateStatus == Types.GuardianStatus.ALLOWED;
  }

  /**
   * @notice True when a funding-mode change armed a replacement for the
   * current window and it has not been used yet.
   * @dev Exposed so off-chain gates can read this answer instead of
   * re-deriving it from `fundingModeTransitionNonce` /
   * `fundingModeReplacementUsedNonce` / `fundingModeTransitionAt`. A mirror
   * would be a second definition of the rule that could silently drift from
   * `_validateFundingWindow`; this returns the replacement predicate that
   * function uses. It omits that function's `expectedWindow > 1` gate, so it
   * can be true before funding starts or during the first window, when every
   * install reverts.
   */
  function isFundingModeReplacementAvailable() external view returns (bool) {
    return _fundingModeReplacementAvailable(expectedFundingWindow());
  }

  /**
   * @dev returns expected on-going funding rate window
   * The first window starts at index 1.
   */
  function expectedFundingWindow() public view returns (uint128) {
    return _expectedFundingWindowAt(_blockTimestamp());
  }

  //===========================================================//
  //                      INTERNAL METHODS
  //===========================================================//

  /**
   * @dev The one install path both funding modes share. Each caller has
   * already established that its mode is the live one; everything after that
   * is identical, so it lives here rather than in two copies that could
   * drift.
   *
   * `_fundingRate` is the rate for one whole funding window, in the same
   * signed e18 representation as {maxFunding}. It is stored per second:
   * {currentFundingRate} and {FundingRateUpdate} have always carried
   * per-second values, and dividing here is what keeps that unchanged.
   *
   * An over-cap rate REVERTS rather than clamping. The submitter clamps to
   * {maxFunding} before submitting, so an over-cap arrival means the
   * off-chain methodology is broken; installing the cap instead would hide
   * that behind a plausible-looking rate. This also matches what the
   * off-chain path has always done.
   */
  function _installFundingRate(int256 _fundingRate) private {
    int256 maxFundingInt = int256(uint256(maxFunding));
    require(
      _fundingRate >= -maxFundingInt && _fundingRate <= maxFundingInt,
      'FundingOracle: funding rate exceeds max funding rate'
    );

    uint128 currentTimestamp = _blockTimestamp();
    uint128 expectedWindow = _expectedFundingWindowAt(currentTimestamp);
    _validateFundingWindow(expectedWindow);

    // funding rate per second
    currentFundingRate = _fundingRate / int256(uint256(FUNDING_RATE_WINDOW));
    windowSet = expectedWindow - 1;

    emit FundingRateUpdate(
      currentFundingRate,
      windowSet,
      (((windowSet + 1) * FUNDING_RATE_WINDOW) + fundingStart) -
        currentTimestamp,
      currentTimestamp
    );
  }

  /**
   * @dev Claims the current window's single rate slot, reverting if it is
   * already taken. State-changing because consuming a mode transition's
   * one-shot replacement has to be recorded.
   */
  function _validateFundingWindow(uint128 expectedWindow) internal {
    require(
      expectedWindow > 1,
      'FundingOracle: funding rate is not settable for 0th window'
    );

    // windowSet is by default 0.
    // windowSet < expectedWindow - 1 means no rate is installed for the
    // current window yet, which is the ordinary case.
    if (windowSet < expectedWindow - 1) {
      // Audit #76 closure: a transition landing in this window's pre-install
      // gap armed a replacement with nothing to replace. This ordinary
      // install IS that window's repair, so it consumes the allowance.
      // Leaving it armed let this install be followed by a second one in the
      // same window, which is the exact invariant the allowance exists to
      // preserve.
      if (_fundingModeReplacementAvailable(expectedWindow)) {
        _consumeFundingModeReplacement(expectedWindow);
      }
      return;
    }

    // A rate IS installed for this window. Rejecting outright treated the
    // prior mode's rate as if it were the one now being requested: a mode
    // change zeroes `currentFundingRate` without touching `windowSet`, so the
    // operator could not install a replacement and funding stayed at zero for
    // the rest of the window — up to nearly a full hour of one side's payment.
    // Permit exactly one replacement per transition instead.
    require(
      _fundingModeReplacementAvailable(expectedWindow),
      'FundingOracle: funding rate for current window is already set'
    );

    _consumeFundingModeReplacement(expectedWindow);
  }

  /**
   * @dev Burns the newest transition's one-shot allowance and emits
   * {FundingModeReplacementApplied}; both consuming paths call it. An allowance
   * can also end without that event: it lapses silently once the clock leaves
   * the transition's window, and {stopFunding} disarms it (logged only as
   * {FundingRateStop}).
   */
  function _consumeFundingModeReplacement(uint128 expectedWindow) private {
    fundingModeReplacementUsedNonce = fundingModeTransitionNonce;
    emit FundingModeReplacementApplied(
      fundingModeTransitionNonce,
      expectedWindow,
      fundingModeTransitionAt
    );
  }

  /**
   * @dev True while the newest mode transition still has its one replacement
   * unused AND the clock has not rolled past the window that transition landed
   * in. Both bounds matter: the nonce stops a second replacement, and the
   * window match stops the allowance from carrying into a later window, where
   * the ordinary path reopens by itself.
   */
  function _fundingModeReplacementAvailable(
    uint128 expectedWindow
  ) private view returns (bool) {
    if (fundingModeTransitionNonce == 0) {
      return false;
    }
    if (fundingModeReplacementUsedNonce == fundingModeTransitionNonce) {
      return false;
    }
    return _expectedFundingWindowAt(fundingModeTransitionAt) == expectedWindow;
  }

  /**
   * @dev Records the cutoff a funding-mode change takes effect at and arms the
   * one replacement rate permitted for what remains of that window.
   *
   * What guarantees the replacement cannot reprice time before the cutoff is
   * the Perpetual side, not the Guardian side: `setFundingRate` and
   * `setOffChainFundingRate` both run `_loadContext(true)` before delegating
   * here, committing the elapsed interval at the OUTGOING rate first.
   */
  function _recordFundingModeTransition(bool onChainAllowed) private {
    uint128 currentTimestamp = _blockTimestamp();
    uint128 expectedWindow = _expectedFundingWindowAt(currentTimestamp);

    fundingModeTransitionNonce += 1;
    fundingModeTransitionAt = currentTimestamp;

    // Seconds of the current nominal window still unpriced at the cutoff.
    // Window `expectedWindow` ends at `fundingStart + expectedWindow * W`.
    uint128 remainingWindowSeconds = expectedWindow == 0
      ? 0
      : (fundingStart + (expectedWindow * FUNDING_RATE_WINDOW)) -
        currentTimestamp;

    emit FundingModeTransition(
      onChainAllowed,
      fundingModeTransitionNonce,
      currentTimestamp,
      remainingWindowSeconds
    );
  }

  function _expectedFundingWindowAt(
    uint128 currentTimestamp
  ) internal view returns (uint128) {
    return
      fundingStart == 0 || currentTimestamp < fundingStart
        ? 0
        : ((currentTimestamp - fundingStart) / FUNDING_RATE_WINDOW) + 1;
  }
}
