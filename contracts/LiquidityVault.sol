// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {IERC20Metadata} from '@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol';
import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {Ownable2StepUpgradeable} from '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {Math} from '@openzeppelin/contracts/utils/math/Math.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';

import {IAccountManager} from './interfaces/IAccountManager.sol';
import {IBackstopVault} from './interfaces/IBackstopVault.sol';
import {IMarginBank} from './interfaces/IMarginBank.sol';
import {SystemAccountHolder} from './SystemAccountHolder.sol';
import {Types} from './libraries/Types.sol';

interface IPerpetualVaultReads {
  function accountFundingAdjustedEquity(
    address account
  ) external view returns (int256 equity);

  /// @dev Read for the one thing that may end NAV tracking: a zero position.
  function getAccountBalance(
    address account
  ) external view returns (Types.PositionBalance memory);
}

contract LiquidityVault is
  Initializable,
  Ownable2StepUpgradeable,
  UUPSUpgradeable,
  // OZ 5.6.1 is @custom:stateless and uses a fixed namespaced slot;
  // issue #32 tests pin these proxy-layout assumptions.
  ReentrancyGuard,
  IBackstopVault
{
  using SafeERC20 for IERC20;

  uint256 public constant MAX_CHILD_VAULTS = 64;
  uint256 public constant MAX_ACTIVE_MARKETS_PER_CHILD = 512;
  uint256 public constant MAX_TOTAL_ACTIVE_CHILD_MARKETS = 1024;

  event BackstopInheritanceAuthorized(
    bytes32 indexed inheritanceId,
    address indexed account,
    address indexed market,
    address inheritingChild,
    Types.PositionBalance inheritedPosition
  );

  event VaultBootstrapped(
    address indexed mainVault,
    address indexed initialChild
  );

  event VaultDeposited(
    bytes32 indexed depositId,
    address indexed lp,
    uint128 amountToken,
    uint256 sharesMinted,
    uint256 navBefore,
    uint256 navAfter
  );

  event VaultWithdrawalRequested(
    bytes32 indexed withdrawId,
    address indexed lp,
    uint256 sharesRequested,
    uint256 unlockAtMs
  );

  event VaultWithdrawalCancelled(
    bytes32 indexed withdrawId,
    address indexed lp,
    uint256 sharesCancelled
  );

  event VaultWithdrawn(
    bytes32 indexed withdrawId,
    address indexed lp,
    uint256 sharesBurned,
    uint128 amountToken,
    uint256 navBefore
  );

  event ChildVaultCreated(
    address indexed child,
    bytes32 indexed label,
    address trader,
    uint256 nonce
  );

  event ChildVaultObserved(address indexed child);
  event ChildVaultActivationUpdate(address indexed child, bool active);
  event ChildVaultTraderUpdate(address indexed child, address trader);
  /// @notice The child trader's permission changed for one market (audit #38).
  /// @dev Distinct from ActiveChildMarketUpdate, which is NAV tracking. The two
  /// were one flag before this issue, which is why disabling routing silently
  /// dropped an open position out of valuation.
  event ChildMarketPermissionUpdate(
    address indexed child,
    address indexed market,
    address indexed trader,
    Types.MarketPermission permission
  );
  event LiquidationChildMapped(address indexed market, address indexed child);
  event LiquidationChildCleared(
    address indexed market,
    address indexed previousChild
  );
  event GuardianUpdate(
    address indexed previousGuardian,
    address indexed newGuardian
  );
  event VaultIncidentSwitchChanged(bytes32 indexed switchName, bool enabled);
  event VaultMarketRegistered(address indexed market, bool active);
  event ActiveChildMarketUpdate(
    address indexed child,
    address indexed market,
    bool active
  );
  event VaultDepositWhitelistEnabledUpdate(bool enabled);
  event VaultDepositorWhitelistUpdate(
    address indexed depositor,
    bool whitelisted
  );
  event VaultPerDepositorDepositCapUpdate(uint128 cap);
  event VaultTotalDepositCapUpdate(uint128 cap);
  event MaxChildVaultsUpdate(uint256 previousValue, uint256 newValue);
  event ActiveChildMarketTrackingInitialized(
    uint256 childCount,
    uint256 activeChildMarketCount
  );

  struct ChildVaultConfig {
    bool activeForRouting;
    bool observed;
    address trader;
    bytes32 label;
  }

  struct WithdrawalRequest {
    address lp;
    uint256 shares;
    uint256 unlockAtMs;
    bool executed;
  }

  address public marginBank;
  address public accountManager;
  address public token;

  address public override mainVaultAddress;

  address public guardian;

  address[] public childVaults;
  mapping(address => ChildVaultConfig) public childVaultConfig;
  mapping(address => bool) public override isRegisteredChildVault;
  mapping(address => address) public liquidationChildForMarket;

  uint256 public totalShares;
  mapping(address => uint256) public sharesOf;
  mapping(bytes32 => WithdrawalRequest) public withdrawalRequests;
  mapping(address => uint256) public pendingWithdrawalSharesOf;
  uint256 public withdrawLockMs;

  bool public bootstrapped;
  bool public childVaultInheritanceHalted;
  bool public riskPaused;
  bool public withdrawalsPaused;
  bool public windDownMode;
  uint256 public maxChildVaults;

  uint256 public childVaultNonce;
  uint256 public backstopInheritanceNonce;
  uint256 public vaultDepositNonce;
  uint256 public vaultWithdrawalRequestNonce;

  mapping(address => bool) public registeredMarket;
  mapping(address => bool) public marketActive;
  address[] public registeredMarkets;
  mapping(address => address[]) public activeChildMarkets;
  mapping(address => mapping(address => bool)) public isActiveChildMarket;

  uint128 public perDepositorVaultDepositCap;
  uint128 public totalVaultDepositCap;
  uint128 public totalNetVaultDeposits;
  bool public vaultDepositWhitelistEnabled;
  mapping(address => bool) public vaultDepositWhitelist;
  mapping(address => uint128) public netVaultDeposits;

  // Appended for the issue #16 migration. Existing deployments can contain
  // duplicate and inactive array entries from the pre-compaction layout, so
  // totalNAV keeps its historical counted-once path until the one-time
  // initializer compacts every child list and establishes these counters.
  uint256 public totalActiveChildMarkets;
  bool public activeChildMarketTrackingInitialized;

  uint256[94] private __gap;

  modifier onlyGuardianOrOwner() {
    require(
      owner() == _msgSender() || guardian == _msgSender(),
      'LiquidityVault: caller is not guardian or owner'
    );
    _;
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function initialize(
    address _marginBank,
    address _accountManager,
    address _token,
    address _owner,
    address _guardian,
    uint256 _withdrawLockMs,
    uint256 _maxChildVaults
  ) external initializer {
    require(_marginBank != address(0), 'LiquidityVault: margin bank zero');
    require(
      _accountManager != address(0),
      'LiquidityVault: account manager zero'
    );
    require(_token != address(0), 'LiquidityVault: token zero');
    require(_owner != address(0), 'LiquidityVault: owner zero');
    require(_guardian != address(0), 'LiquidityVault: guardian zero');
    require(
      _maxChildVaults > 0 && _maxChildVaults <= MAX_CHILD_VAULTS,
      'LiquidityVault: invalid max children'
    );

    marginBank = _marginBank;
    accountManager = _accountManager;
    token = _token;
    require(
      IERC20Metadata(_token).decimals() == 18,
      'LiquidityVault: collateral must have 18 decimals'
    );
    guardian = _guardian;
    withdrawLockMs = _withdrawLockMs;
    maxChildVaults = _maxChildVaults;
    vaultDepositWhitelistEnabled = true;
    activeChildMarketTrackingInitialized = true;

    __Ownable_init(_owner);
    __Ownable2Step_init();

    emit VaultDepositWhitelistEnabledUpdate(true);
    vaultDepositWhitelist[_owner] = true;
    emit VaultDepositorWhitelistUpdate(_owner, true);
  }

  function bootstrapVaultAccounts(
    bytes32 mainLabel,
    bytes32 initialChildLabel,
    address initialTrader
  ) external onlyOwner nonReentrant {
    require(!bootstrapped, 'LiquidityVault: already bootstrapped');
    require(maxChildVaults > 0, 'LiquidityVault: max child vaults zero');

    mainVaultAddress = _deploySystemAccount(mainLabel, 0);
    // Registered in both contracts even though the main account never receives
    // an operator, so one inventory covers both bindings and no operator has to
    // reason about which accounts belong where.
    IMarginBank(marginBank).registerSystemAccount(mainVaultAddress);
    IAccountManager(accountManager).registerSystemAccount(mainVaultAddress);

    address initialChild = _createChildVault(initialChildLabel, initialTrader);
    bootstrapped = true;
    emit VaultBootstrapped(mainVaultAddress, initialChild);
  }

  function setMaxChildVaults(uint256 value) external onlyOwner {
    require(
      value > 0 && value <= MAX_CHILD_VAULTS,
      'LiquidityVault: invalid max children'
    );
    require(value >= childVaults.length, 'LiquidityVault: below child count');
    uint256 previousValue = maxChildVaults;
    maxChildVaults = value;
    emit MaxChildVaultsUpdate(previousValue, value);
  }

  /// @notice Compacts historical child-market arrays after upgrading a live
  /// proxy. This migration bridge is required because pre-upgrade arrays may
  /// contain duplicate and inactive entries that durable proxy storage keeps.
  function initializeActiveChildMarketTracking()
    external
    reinitializer(2)
    onlyOwner
  {
    require(
      !activeChildMarketTrackingInitialized,
      'LiquidityVault: tracking initialized'
    );
    require(
      childVaults.length <= MAX_CHILD_VAULTS,
      'LiquidityVault: too many children'
    );

    if (maxChildVaults > MAX_CHILD_VAULTS) {
      uint256 previousValue = maxChildVaults;
      maxChildVaults = MAX_CHILD_VAULTS;
      emit MaxChildVaultsUpdate(previousValue, MAX_CHILD_VAULTS);
    }

    uint256 activeMarketCount = 0;
    for (uint256 i = 0; i < childVaults.length; i++) {
      activeMarketCount += _compactActiveChildMarkets(childVaults[i]);
    }
    require(
      activeMarketCount <= MAX_TOTAL_ACTIVE_CHILD_MARKETS,
      'LiquidityVault: too many active markets'
    );

    totalActiveChildMarkets = activeMarketCount;
    activeChildMarketTrackingInitialized = true;
    emit ActiveChildMarketTrackingInitialized(
      childVaults.length,
      activeMarketCount
    );
  }

  function setGuardian(address newGuardian) external onlyOwner {
    require(newGuardian != address(0), 'LiquidityVault: guardian zero');
    address previousGuardian = guardian;
    guardian = newGuardian;
    emit GuardianUpdate(previousGuardian, newGuardian);
  }

  function setVaultDepositWhitelistEnabled(bool enabled) external onlyOwner {
    vaultDepositWhitelistEnabled = enabled;
    emit VaultDepositWhitelistEnabledUpdate(enabled);
  }

  function setVaultDepositWhitelist(
    address[] calldata depositors,
    bool whitelisted
  ) external onlyOwner {
    for (uint256 i = 0; i < depositors.length; i++) {
      address depositor = depositors[i];
      require(depositor != address(0), 'LiquidityVault: depositor zero');
      vaultDepositWhitelist[depositor] = whitelisted;
      emit VaultDepositorWhitelistUpdate(depositor, whitelisted);
    }
  }

  /**
   * @notice Sets the maximum tracked token deposits allowed per depositor.
   * @dev The cap applies prospectively to future deposits and may be lower
   * than a depositor's existing tracked deposits. New deposits remain blocked
   * until withdrawals create enough headroom under the cap. A zero value
   * disables this cap; it does not pause deposits. To pause deposits, enable
   * riskPaused or windDownMode through setVaultIncidentSwitch.
   * @param cap Maximum tracked token deposits per depositor, or zero for no
   * per-depositor cap.
   */
  function setPerDepositorVaultDepositCap(uint128 cap) external onlyOwner {
    perDepositorVaultDepositCap = cap;
    emit VaultPerDepositorDepositCapUpdate(cap);
  }

  /**
   * @notice Sets the maximum tracked token deposits allowed across the vault.
   * @dev The cap applies prospectively to future deposits and may be lower
   * than the vault's existing tracked deposits. New deposits remain blocked
   * until withdrawals create enough headroom under the cap. A zero value
   * disables this cap; it does not pause deposits. To pause deposits, enable
   * riskPaused or windDownMode through setVaultIncidentSwitch.
   * @param cap Maximum tracked token deposits across the vault, or zero for no
   * total cap.
   */
  function setTotalVaultDepositCap(uint128 cap) external onlyOwner {
    totalVaultDepositCap = cap;
    emit VaultTotalDepositCapUpdate(cap);
  }

  function createChildVault(
    bytes32 label,
    address trader
  ) external onlyOwner nonReentrant returns (address child) {
    child = _createChildVault(label, trader);
  }

  /**
   * @notice Re-registers an account this vault already owns with MarginBank and
   *         AccountManager.
   * @dev The audit #70 binding is append-only and, apart from this, the vault
   * only registers accounts at `bootstrapVaultAccounts` (one-shot) and
   * `createChildVault` (freshly deployed children). Without this entry point an
   * account the binding migration omitted could never be bound by anyone —
   * the holder's `controller()` is immutable and only this vault satisfies it —
   * so its balance would be frozen until another vault upgrade.
   *
   * It grants no new authority: `account` must already be this vault's main
   * account or one of its registered children, and both registries independently
   * re-prove the holder shape.
   *
   * Each registry is registered independently, because they can disagree: a
   * campaign that migrated one proxy and failed on the other leaves an account
   * bound in one and not the other. Re-running on an already-bound account is a
   * silent no-op rather than a revert, so an operator can call it per account
   * without first working out which side is missing.
   */
  function registerExistingSystemAccount(
    address account
  ) external onlyOwner nonReentrant {
    require(
      account == mainVaultAddress || isRegisteredChildVault[account],
      'LiquidityVault: unknown system account'
    );
    if (IMarginBank(marginBank).controllerOf(account) == address(0)) {
      IMarginBank(marginBank).registerSystemAccount(account);
    }
    if (IAccountManager(accountManager).controllerOf(account) == address(0)) {
      IAccountManager(accountManager).registerSystemAccount(account);
    }
  }

  function markChildObserved(address child) external onlyOwner {
    _requireRegisteredChild(child);
    childVaultConfig[child].observed = true;
    emit ChildVaultObserved(child);
  }

  function setChildActiveForRouting(
    address child,
    bool active
  ) external onlyOwner {
    _requireRegisteredChild(child);
    if (active) {
      require(
        childVaultConfig[child].observed,
        'LiquidityVault: child not observed'
      );
      require(
        childVaultConfig[child].trader != address(0),
        'LiquidityVault: child trader missing'
      );
    }
    childVaultConfig[child].activeForRouting = active;
    emit ChildVaultActivationUpdate(child, active);
  }

  function setChildTrader(address child, address trader) external onlyOwner {
    _requireRegisteredChild(child);
    require(
      trader != address(0) || !childVaultConfig[child].activeForRouting,
      'LiquidityVault: active child needs trader'
    );
    address oldTrader = childVaultConfig[child].trader;
    // Guarded rather than unconditional: with the transfer below, re-setting the
    // SAME trader would grant its permissions and then immediately revoke them,
    // silently disarming a child the owner only meant to touch idempotently.
    if (oldTrader != address(0) && oldTrader != trader) {
      IAccountManager(accountManager).setSystemSubAccount(
        child,
        oldTrader,
        false
      );
      // Audit #38: authority is per-market now, so a rotation has to MOVE it.
      // Clearing the global flag no longer stops the departing trader, and
      // granting the incoming one nothing would leave a live position unmanaged
      // until the owner re-stated every market by hand. Transferring keeps the
      // role continuous on every tracked market: same markets, same modes, one
      // call.
      //
      // Any revert in this call undoes the whole rotation; that comes from the
      // transaction, not from the grant-then-revoke order inside the loop.
      //
      // Bounded by the child's own tracked-market list — the same list
      // totalNAV() already walks on every deposit and withdrawal, so this adds
      // no new assumption about how many markets a child may track.
      address[] storage markets = activeChildMarkets[child];
      for (uint256 i = 0; i < markets.length; i++) {
        address market = markets[i];
        Types.MarketPermission permission = IAccountManager(accountManager)
          .systemMarketPermission(child, oldTrader, market);
        if (permission == Types.MarketPermission.NONE) continue;

        if (trader != address(0)) {
          IAccountManager(accountManager).setSystemMarketPermission(
            child,
            trader,
            market,
            permission
          );
          emit ChildMarketPermissionUpdate(child, market, trader, permission);
        }
        IAccountManager(accountManager).setSystemMarketPermission(
          child,
          oldTrader,
          market,
          Types.MarketPermission.NONE
        );
        emit ChildMarketPermissionUpdate(
          child,
          market,
          oldTrader,
          Types.MarketPermission.NONE
        );
      }
    }
    childVaultConfig[child].trader = trader;
    emit ChildVaultTraderUpdate(child, trader);
  }

  function setVaultIncidentSwitch(
    bytes32 switchName,
    bool enabled
  ) external onlyGuardianOrOwner {
    bool ownerOnlySwitch = switchName == 'withdrawalsPaused' ||
      switchName == 'windDownMode';
    if (ownerOnlySwitch) {
      require(owner() == _msgSender(), 'LiquidityVault: owner switch');
    }

    if (switchName == 'childVaultInheritanceHalted') {
      childVaultInheritanceHalted = enabled;
    } else if (switchName == 'riskPaused') {
      riskPaused = enabled;
    } else if (switchName == 'withdrawalsPaused') {
      withdrawalsPaused = enabled;
    } else if (switchName == 'windDownMode') {
      windDownMode = enabled;
    } else {
      revert('LiquidityVault: unknown switch');
    }
    emit VaultIncidentSwitchChanged(switchName, enabled);
  }

  function registerMarket(address market, bool active) external onlyOwner {
    require(market != address(0), 'LiquidityVault: market zero');
    if (!registeredMarket[market]) {
      registeredMarkets.push(market);
    }
    registeredMarket[market] = true;
    marketActive[market] = active;
    emit VaultMarketRegistered(market, active);
  }

  function setChildActiveForMarket(
    address child,
    address market,
    bool active
  ) external onlyOwner {
    _setChildActiveForMarket(child, market, active);
  }

  /**
   * @notice Sets what the child's trader may do in one market (audit #38).
   * @dev Trading permission, NOT valuation. Moving to `REDUCE_ONLY` or `NONE`
   * deliberately leaves the pair in `activeChildMarkets`, so a position the
   * child still holds keeps counting toward `totalNAV()`. Untracking it is a
   * separate call that requires the position to actually be zero.
   *
   * Granting `ACTIVE` requires the pair to be tracked first: a market whose
   * position would not reach NAV must not be allowed to take on risk. That is
   * the exact pairing whose absence is the finding.
   */
  function setChildMarketPermission(
    address child,
    address market,
    Types.MarketPermission permission
  ) external onlyOwner {
    _requireRegisteredChild(child);
    require(registeredMarket[market], 'LiquidityVault: market unknown');
    address trader = childVaultConfig[child].trader;
    require(trader != address(0), 'LiquidityVault: child trader missing');
    if (permission == Types.MarketPermission.ACTIVE) {
      require(
        isActiveChildMarket[child][market],
        'LiquidityVault: market not tracked'
      );
      require(
        marketActive[market],
        'LiquidityVault: market inactive'
      );
      require(
        childVaultConfig[child].activeForRouting,
        'LiquidityVault: child inactive'
      );
    }
    IAccountManager(accountManager).setSystemMarketPermission(
      child,
      trader,
      market,
      permission
    );
    emit ChildMarketPermissionUpdate(child, market, trader, permission);
  }

  /**
   * @notice Clears a child's pre-#38 global sub-account approval.
   * @dev The migration's third step, and deliberately a separate call from
   * writing the permissions: the audit's order is populate, VERIFY, then revoke.
   * Doing it in one transaction would remove the point at which an operator
   * confirms every replacement permission actually landed.
   *
   * Safe to run late because the approval is already inert — no authorization
   * path reads `subAccounts` for a system account once #38 is deployed — but
   * leaving it set would misreport the child's authority to anyone reading
   * `isSubAccount`, so it does not just get abandoned.
   *
   * Only this vault's own children. A superseded vault's children keep their
   * (inert) approvals, because only the controller an account is bound to may
   * clear one and those implementations have no such call.
   */
  function revokeChildGlobalApproval(
    address child,
    address trader
  ) external onlyOwner {
    _requireRegisteredChild(child);
    require(trader != address(0), 'LiquidityVault: trader zero');
    IAccountManager(accountManager).setSystemSubAccount(child, trader, false);
  }

  /**
   * @notice The child's on-chain position quantity in a market.
   * @dev The gate for ending NAV tracking. Read from the market rather than
   * from vault bookkeeping so untracking cannot be based on a stale local view.
   */
  function childMarketPositionQuantity(
    address child,
    address market
  ) public view returns (uint128) {
    return IPerpetualVaultReads(market).getAccountBalance(child).qPos;
  }

  function _setChildActiveForMarket(
    address child,
    address market,
    bool active
  ) internal {
    _requireRegisteredChild(child);
    require(registeredMarket[market], 'LiquidityVault: market unknown');
    require(
      activeChildMarketTrackingInitialized,
      'LiquidityVault: tracking not initialized'
    );
    if (!active) {
      require(
        liquidationChildForMarket[market] != child,
        'LiquidityVault: child is liquidation route'
      );
      // Audit #38: untracking is what removes a pair from totalNAV(), so it may
      // only happen once there is nothing left to value. Previously this call
      // could drop an open position out of NAV, understating what the vault
      // actually owed or owned. Reaching zero is always possible — closing,
      // liquidation, and delisting settlement all stay permitted under
      // REDUCE_ONLY.
      require(
        childMarketPositionQuantity(child, market) == 0,
        'LiquidityVault: child position open'
      );
      // ACTIVE => tracked was previously enforced only at grant time, so
      // untracking left the trader ACTIVE on a market NAV no longer values —
      // the exact hole #38 closes, reachable by an owner sequence. Untracking
      // now demotes the current trader to NONE. Safe here: the position is
      // provably zero, so there is nothing left to wind down, and re-tracking
      // requires a fresh explicit grant. This also removes the only way an
      // ACTIVE permission could survive onto an untracked market, which is what
      // made rotation able to leave a departed trader armed there.
      address trader = childVaultConfig[child].trader;
      if (trader != address(0)) {
        Types.MarketPermission current = IAccountManager(accountManager)
          .systemMarketPermission(child, trader, market);
        if (current != Types.MarketPermission.NONE) {
          IAccountManager(accountManager).setSystemMarketPermission(
            child,
            trader,
            market,
            Types.MarketPermission.NONE
          );
          emit ChildMarketPermissionUpdate(
            child,
            market,
            trader,
            Types.MarketPermission.NONE
          );
        }
      }
    }
    bool wasActive = isActiveChildMarket[child][market];
    if (active && !wasActive) {
      address[] storage markets = activeChildMarkets[child];
      require(
        markets.length < MAX_ACTIVE_MARKETS_PER_CHILD,
        'LiquidityVault: child market limit'
      );
      require(
        totalActiveChildMarkets < MAX_TOTAL_ACTIVE_CHILD_MARKETS,
        'LiquidityVault: total market limit'
      );
      markets.push(market);
      totalActiveChildMarkets += 1;
    } else if (!active && wasActive) {
      _removeActiveChildMarket(child, market);
      totalActiveChildMarkets -= 1;
    }
    isActiveChildMarket[child][market] = active;
    emit ActiveChildMarketUpdate(child, market, active);
  }

  function setLiquidationChildForMarket(
    address market,
    address child
  ) external onlyOwner {
    require(registeredMarket[market], 'LiquidityVault: market unknown');
    _requireActiveChild(child);
    _setChildActiveForMarket(child, market, true);
    liquidationChildForMarket[market] = child;
    emit LiquidationChildMapped(market, child);
  }

  function clearLiquidationChildForMarket(address market) external onlyOwner {
    require(registeredMarket[market], 'LiquidityVault: market unknown');
    address previousChild = liquidationChildForMarket[market];
    require(
      previousChild != address(0),
      'LiquidityVault: liquidation route missing'
    );
    liquidationChildForMarket[market] = address(0);
    emit LiquidationChildCleared(market, previousChild);
  }

  function deposit(
    uint128 amountToken
  ) external nonReentrant returns (uint256 shares) {
    require(bootstrapped, 'LiquidityVault: not bootstrapped');
    require(!riskPaused && !windDownMode, 'LiquidityVault: deposits paused');
    require(amountToken > 0, 'LiquidityVault: invalid amount');
    _recordVaultDeposit(_msgSender(), amountToken);

    uint256 navBefore = totalShares == 0 ? 0 : totalNAV();
    IERC20(token).safeTransferFrom(_msgSender(), marginBank, amountToken);
    IMarginBank(marginBank).depositStrandedSystemAccountToken(
      _msgSender(),
      mainVaultAddress,
      amountToken
    );

    uint256 amountE18 = amountToken;
    shares = totalShares == 0
      ? amountE18
      : (amountE18 * totalShares) / navBefore;
    require(shares > 0, 'LiquidityVault: zero shares');
    totalShares += shares;
    sharesOf[_msgSender()] += shares;

    vaultDepositNonce += 1;

    uint256 navAfter = totalNAV();
    bytes32 depositId = keccak256(
      abi.encode(block.chainid, address(this), _msgSender(), vaultDepositNonce)
    );
    emit VaultDeposited(
      depositId,
      _msgSender(),
      amountToken,
      shares,
      navBefore,
      navAfter
    );
  }

  function requestWithdrawal(
    uint256 shares
  ) external nonReentrant returns (bytes32 withdrawId) {
    require(bootstrapped, 'LiquidityVault: not bootstrapped');
    require(shares > 0, 'LiquidityVault: invalid shares');
    require(
      pendingWithdrawalSharesOf[_msgSender()] == 0,
      'LiquidityVault: pending withdrawal'
    );
    require(
      sharesOf[_msgSender()] >= shares,
      'LiquidityVault: insufficient shares'
    );

    uint256 unlockAtMs = (block.timestamp * 1000) + withdrawLockMs;
    vaultWithdrawalRequestNonce += 1;
    withdrawId = keccak256(
      abi.encode(
        block.chainid,
        address(this),
        _msgSender(),
        shares,
        vaultWithdrawalRequestNonce
      )
    );
    pendingWithdrawalSharesOf[_msgSender()] = shares;
    withdrawalRequests[withdrawId] = WithdrawalRequest({
      lp: _msgSender(),
      shares: shares,
      unlockAtMs: unlockAtMs,
      executed: false
    });
    emit VaultWithdrawalRequested(withdrawId, _msgSender(), shares, unlockAtMs);
  }

  function cancelWithdrawal(bytes32 withdrawId) external nonReentrant {
    require(bootstrapped, 'LiquidityVault: not bootstrapped');
    WithdrawalRequest storage request = withdrawalRequests[withdrawId];
    require(request.lp != address(0), 'LiquidityVault: withdrawal missing');
    require(request.lp == _msgSender(), 'LiquidityVault: withdrawal owner');
    require(!request.executed, 'LiquidityVault: withdrawal executed');

    uint256 shares = request.shares;
    require(
      pendingWithdrawalSharesOf[request.lp] >= shares,
      'LiquidityVault: pending shares'
    );

    request.executed = true;
    pendingWithdrawalSharesOf[request.lp] -= shares;
    emit VaultWithdrawalCancelled(withdrawId, request.lp, shares);
  }

  function executeWithdrawal(
    bytes32 withdrawId
  ) external nonReentrant returns (uint128 amountToken) {
    require(bootstrapped, 'LiquidityVault: not bootstrapped');
    require(!withdrawalsPaused, 'LiquidityVault: withdrawals paused');
    WithdrawalRequest storage request = withdrawalRequests[withdrawId];
    require(request.lp != address(0), 'LiquidityVault: withdrawal missing');
    require(request.lp == _msgSender(), 'LiquidityVault: withdrawal owner');
    require(!request.executed, 'LiquidityVault: withdrawal executed');
    require(
      block.timestamp * 1000 >= request.unlockAtMs,
      'LiquidityVault: locked'
    );

    uint256 shares = request.shares;
    uint256 lpSharesBefore = sharesOf[request.lp];
    require(lpSharesBefore >= shares, 'LiquidityVault: insufficient shares');
    require(
      pendingWithdrawalSharesOf[request.lp] >= shares,
      'LiquidityVault: pending shares'
    );

    uint256 navBefore = totalNAV();
    uint256 payoutE18 = (shares * navBefore) / totalShares;
    uint256 tokenAmount = payoutE18;
    require(tokenAmount > 0, 'LiquidityVault: zero payout');
    require(
      tokenAmount <= type(uint128).max,
      'LiquidityVault: payout overflow'
    );

    uint128 withdrawAmountE18 = uint128(tokenAmount);
    require(
      IMarginBank(marginBank).getAccountBankBalance(mainVaultAddress) >=
        withdrawAmountE18,
      'LiquidityVault: insufficient Main liquidity'
    );

    request.executed = true;
    pendingWithdrawalSharesOf[request.lp] -= shares;
    sharesOf[request.lp] -= shares;
    totalShares -= shares;
    _recordVaultWithdrawal(request.lp, shares, lpSharesBefore);
    IMarginBank(marginBank).withdrawFromSystemAccount(
      mainVaultAddress,
      request.lp,
      withdrawAmountE18
    );

    amountToken = uint128(tokenAmount);
    emit VaultWithdrawn(withdrawId, request.lp, shares, amountToken, navBefore);
  }

  function fundChild(
    address child,
    uint128 amountE18
  ) external onlyOwner nonReentrant {
    _requireActiveChild(child);
    require(!riskPaused && !windDownMode, 'LiquidityVault: funding paused');
    IMarginBank(marginBank).transferFromSystemAccount(
      mainVaultAddress,
      child,
      amountE18
    );
  }

  function returnChildLiquidity(
    address child,
    uint128 amountE18
  ) external onlyOwner nonReentrant {
    _requireRegisteredChild(child);
    IMarginBank(marginBank).transferFromSystemAccount(
      child,
      mainVaultAddress,
      amountE18
    );
  }

  /**
   * @notice Authorizes the routed child to receive a distressed position.
   * @dev The market caller enforces the positive-equity backstop trigger before
   * calling. Remaining isolated margin moves with the position, and its positive
   * residual equity is retained by the child as the insurance fee for assuming
   * tail risk rather than refunded to the source account.
   */
  function inheritPosition(
    address account,
    address market,
    Types.PositionBalance calldata position
  )
    external
    override
    nonReentrant
    returns (bytes32 inheritanceId, address child)
  {
    require(bootstrapped, 'LiquidityVault: not bootstrapped');
    require(!childVaultInheritanceHalted, 'LiquidityVault: inheritance halted');
    require(!riskPaused && !windDownMode, 'LiquidityVault: risk paused');
    require(market == _msgSender(), 'LiquidityVault: caller not market');
    require(marketActive[market], 'LiquidityVault: market inactive');
    require(account != mainVaultAddress, 'LiquidityVault: Main source');
    require(!isRegisteredChildVault[account], 'LiquidityVault: child source');
    require(position.qPos > 0, 'LiquidityVault: empty position');

    child = liquidationChildForMarket[market];
    require(child != address(0), 'LiquidityVault: liquidation route missing');
    _requireActiveChild(child);

    backstopInheritanceNonce += 1;
    inheritanceId = keccak256(
      abi.encode(
        block.chainid,
        address(this),
        market,
        account,
        child,
        backstopInheritanceNonce
      )
    );

    emit BackstopInheritanceAuthorized(
      inheritanceId,
      account,
      market,
      child,
      position
    );
  }

  function totalNAV() public view returns (uint256) {
    int256 nav = int256(
      uint256(IMarginBank(marginBank).getAccountBankBalance(mainVaultAddress))
    );

    for (
      uint256 childIndex = 0;
      childIndex < childVaults.length;
      childIndex++
    ) {
      address child = childVaults[childIndex];
      nav += int256(
        uint256(IMarginBank(marginBank).getAccountBankBalance(child))
      );

      address[] storage markets = activeChildMarkets[child];
      for (
        uint256 marketIndex = 0;
        marketIndex < markets.length;
        marketIndex++
      ) {
        address market = markets[marketIndex];
        if (!isActiveChildMarket[child][market]) {
          continue;
        }
        if (
          !activeChildMarketTrackingInitialized &&
          !_isFirstTrackedMarketOccurrence(markets, marketIndex)
        ) {
          continue;
        }
        nav += childVaultMarketEquity(child, market);
      }
    }

    require(nav > 0, 'LiquidityVault: NAV non-positive');
    return uint256(nav);
  }

  function childVaultMarketEquity(
    address child,
    address market
  ) public view returns (int256) {
    _requireRegisteredChild(child);
    require(registeredMarket[market], 'LiquidityVault: market unknown');
    return IPerpetualVaultReads(market).accountFundingAdjustedEquity(child);
  }

  function _isFirstTrackedMarketOccurrence(
    address[] storage markets,
    uint256 marketIndex
  ) internal view returns (bool) {
    address market = markets[marketIndex];
    for (uint256 i = 0; i < marketIndex; i++) {
      if (markets[i] == market) {
        return false;
      }
    }
    return true;
  }

  function _compactActiveChildMarkets(
    address child
  ) internal returns (uint256 activeMarketCount) {
    address[] storage markets = activeChildMarkets[child];
    uint256 writeIndex = 0;

    for (uint256 readIndex = 0; readIndex < markets.length; readIndex++) {
      address market = markets[readIndex];
      if (!isActiveChildMarket[child][market]) {
        continue;
      }

      bool alreadyKept = false;
      for (uint256 i = 0; i < writeIndex; i++) {
        if (markets[i] == market) {
          alreadyKept = true;
          break;
        }
      }
      if (alreadyKept) {
        continue;
      }

      markets[writeIndex] = market;
      writeIndex += 1;
    }

    require(
      writeIndex <= MAX_ACTIVE_MARKETS_PER_CHILD,
      'LiquidityVault: child market limit'
    );
    while (markets.length > writeIndex) {
      markets.pop();
    }
    return writeIndex;
  }

  function _removeActiveChildMarket(address child, address market) internal {
    address[] storage markets = activeChildMarkets[child];
    for (uint256 i = 0; i < markets.length; i++) {
      if (markets[i] != market) {
        continue;
      }
      uint256 lastIndex = markets.length - 1;
      if (i != lastIndex) {
        markets[i] = markets[lastIndex];
      }
      markets.pop();
      return;
    }
    revert('LiquidityVault: active market missing');
  }

  /// @notice Number of markets ever registered with the vault (audit #38
  /// follow-up). Exists so off-chain tooling can enumerate registeredMarkets
  /// exactly instead of probing indices until a revert — a probe loop cannot
  /// tell end-of-array from a transient RPC error, and off-chain checks for
  /// stranded positions depend on seeing the full universe.
  function registeredMarketCount() external view returns (uint256) {
    return registeredMarkets.length;
  }

  function childVaultCount() external view returns (uint256) {
    return childVaults.length;
  }

  function activeChildMarketCount(
    address child
  ) external view returns (uint256) {
    _requireRegisteredChild(child);
    return activeChildMarkets[child].length;
  }

  function _createChildVault(
    bytes32 label,
    address trader
  ) internal returns (address child) {
    require(
      childVaults.length < MAX_CHILD_VAULTS,
      'LiquidityVault: hard max children'
    );
    require(
      childVaults.length < maxChildVaults,
      'LiquidityVault: max children'
    );
    require(label != bytes32(0), 'LiquidityVault: label zero');
    require(trader != address(0), 'LiquidityVault: trader zero');

    childVaultNonce += 1;
    child = _deploySystemAccount(label, childVaultNonce);
    childVaults.push(child);
    isRegisteredChildVault[child] = true;
    childVaultConfig[child] = ChildVaultConfig({
      activeForRouting: false,
      observed: false,
      trader: trader,
      label: label
    });
    IMarginBank(marginBank).registerSystemAccount(child);
    IAccountManager(accountManager).registerSystemAccount(child);
    // Audit #38: no global approval. It is what let a child trader sign in
    // markets the vault never assigned, producing positions that changed real
    // assets without changing reported NAV. A new child starts with authority
    // over nothing; the owner tracks a market, then grants ACTIVE for it.

    emit ChildVaultCreated(child, label, trader, childVaultNonce);
  }

  function _deploySystemAccount(
    bytes32 label,
    uint256 nonce
  ) internal returns (address) {
    bytes32 salt = keccak256(
      abi.encode(block.chainid, address(this), label, nonce)
    );
    SystemAccountHolder holder = new SystemAccountHolder{salt: salt}(
      address(this)
    );
    return address(holder);
  }

  function _requireRegisteredChild(address child) internal view {
    require(isRegisteredChildVault[child], 'LiquidityVault: unknown child');
  }

  function _requireActiveChild(address child) internal view {
    _requireRegisteredChild(child);
    require(
      childVaultConfig[child].activeForRouting,
      'LiquidityVault: child inactive'
    );
    require(
      childVaultConfig[child].trader != address(0),
      'LiquidityVault: child trader missing'
    );
  }

  function _recordVaultDeposit(
    address depositor,
    uint128 amountToken
  ) internal {
    if (vaultDepositWhitelistEnabled) {
      require(
        vaultDepositWhitelist[depositor],
        'LiquidityVault: depositor not whitelisted'
      );
    }

    uint256 nextDepositorDepositAmount = uint256(netVaultDeposits[depositor]) +
      amountToken;
    require(
      nextDepositorDepositAmount <= type(uint128).max,
      'LiquidityVault: net deposits overflow'
    );
    if (perDepositorVaultDepositCap > 0) {
      require(
        nextDepositorDepositAmount <= perDepositorVaultDepositCap,
        'LiquidityVault: depositor cap exceeded'
      );
    }

    uint256 nextTotalDepositAmount = uint256(totalNetVaultDeposits) +
      amountToken;
    require(
      nextTotalDepositAmount <= type(uint128).max,
      'LiquidityVault: total net deposits overflow'
    );
    if (totalVaultDepositCap > 0) {
      require(
        nextTotalDepositAmount <= totalVaultDepositCap,
        'LiquidityVault: total cap exceeded'
      );
    }

    netVaultDeposits[depositor] = uint128(nextDepositorDepositAmount);
    totalNetVaultDeposits = uint128(nextTotalDepositAmount);
  }

  function _recordVaultWithdrawal(
    address depositor,
    uint256 sharesBurned,
    uint256 sharesBefore
  ) internal {
    uint128 currentDeposits = netVaultDeposits[depositor];
    if (currentDeposits == 0) {
      return;
    }

    if (sharesBurned >= sharesBefore) {
      netVaultDeposits[depositor] = 0;
      _reduceTotalNetVaultDeposits(currentDeposits);
      return;
    }

    uint256 reduction = Math.mulDiv(
      uint256(currentDeposits),
      sharesBurned,
      sharesBefore,
      Math.Rounding.Floor
    );
    require(reduction <= currentDeposits, 'LiquidityVault: invalid reduction');

    netVaultDeposits[depositor] = currentDeposits - uint128(reduction);
    _reduceTotalNetVaultDeposits(uint128(reduction));
  }

  function _reduceTotalNetVaultDeposits(uint128 reduction) internal {
    if (reduction >= totalNetVaultDeposits) {
      totalNetVaultDeposits = 0;
      return;
    }

    totalNetVaultDeposits -= reduction;
  }

  function _authorizeUpgrade(
    address newImplementation
  ) internal override onlyOwner {}
}
