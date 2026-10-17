// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

import {AggregatorV3Interface} from '@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol';
import {Ownable2Step} from '@openzeppelin/contracts/access/Ownable2Step.sol';
import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';

/**
 * @title ImmutableBackendPriceOracle
 * @author MNX Markets <help@mnx.fi>
 * @notice Non-upgradeable AggregatorV3-compatible oracle updated by a
 * permissioned backend. Configuration and metadata are fixed at deployment;
 * the owner and updater roles remain mutable. There is no proxy or upgrade
 * path.
 *
 * Audit #79 closed the future-dated-round class at the CHECKER: Perpetual
 * rejects `updatedAt > block.timestamp` at oracle installation and on the
 * index-updating path. That check cannot close the class on its own, because
 * an upgradeable oracle can change behaviour underneath a stable address
 * after every check has passed. This contract closes it at the PRODUCER:
 *
 *   - There is no proxy, no initializer, and no admin upgrade path. The code
 *     at this address is the code that was deployed.
 *   - `updatedAt` is generated internally from `block.timestamp` at
 *     acceptance. Publishers supply only the price, so a future-dated round
 *     is unrepresentable BY CONSTRUCTION rather than by validation.
 *   - Round ids are monotone from 1, and `answeredInRound == roundId` on
 *     every round this contract can produce.
 *
 * Reading block time here is permitted: these setters run on the updater
 * lane, never on the trade path, so they do not drop the transaction to
 * MegaETH's lower compute ceiling for volatile context.
 *
 * What is immutable and what is not:
 *   - CODE is immutable. Per-deployment configuration (`maxUpdateBps`,
 *     `maxStalenessSeconds`, `minUpdateIntervalSeconds`, `decimals`) is a
 *     constructor `immutable`. Changing any of it means deploying a
 *     replacement and rotating through `Perpetual.setOracle`, which is the
 *     model audit #53 decided: bounds change via oracle replacement, so the
 *     change passes the install-time continuity and capacity checks that a
 *     proxy upgrade bypassed entirely.
 *   - ROLES are mutable state. The updater set and the owner keep the audit
 *     #77 rotation machinery (`setUpdater`, `rotateUpdater`), because
 *     retiring a compromised publishing key must not require redeploying and
 *     re-installing an oracle.
 *
 * Owner and updater stay independent roles: owning the contract does not
 * authorize publishing prices. Multiple simultaneous updaters are
 * intentional so a replacement publisher can be granted and verified before
 * the incumbent is retired.
 */
contract ImmutableBackendPriceOracle is AggregatorV3Interface, Ownable2Step {
  /// @notice Protocol price scaling. Perpetual requires exactly 18 ('P45') at
  /// installation, so any other value produces an oracle that can be minted
  /// but never installed. Kept a constructor parameter rather than a constant
  /// so the type surface stays open, and pinned by the factory.
  uint8 private immutable _decimals;

  uint256 public constant override version = 1;

  /// @notice Human-readable feed label. Solidity cannot mark reference types
  /// `immutable`, so this is storage with no setter — immutable in the sense
  /// that matters: no function can change it.
  string private _description;

  // updater role — mutable state, see the contract-level note on audit #77
  mapping(address => bool) public updaters;

  /// @notice Advisory maximum age in seconds; 0 disables. Consumers enforce
  /// their own bound against `updatedAt` (Perpetual has its own
  /// `oracleMaxStalenessSeconds`), so this is operational monitoring.
  uint128 public immutable maxStalenessSeconds;

  /// @notice Maximum per-update change in basis points. Perpetual's ADL
  /// replacement-capacity invariant staticcalls this and requires a usable
  /// bound ('P54'), and the audit #53 continuity check measures an oracle
  /// swap against the stricter of the two feeds' values.
  uint128 public immutable maxUpdateBps;

  /// @notice Minimum seconds between accepted updates; 0 disables.
  uint128 public immutable minUpdateIntervalSeconds;

  // round storage
  uint80 internal _latestRound;
  uint256 public lastUpdateBlock;
  mapping(uint80 => int256) internal _answers; // 18-dec scaled
  mapping(uint80 => uint256) private _startedAt;
  mapping(uint80 => uint256) private _updatedAt;

  event UpdaterSet(address account, bool isAuthorized);
  /// @notice Atomic updater handoff evidence. Always accompanied by the two
  /// matching UpdaterSet events so existing consumers see the same facts.
  event UpdaterRotated(
    address indexed previousUpdater,
    address indexed newUpdater
  );
  /// @notice Emitted once at construction. Kept for parity with the
  /// upgradeable oracle's event stream so the same indexer reads both; there
  /// is deliberately no setter that could emit it a second time.
  event ConfigSet(
    uint128 maxStalenessSeconds,
    uint128 maxUpdateBps,
    uint128 minUpdateIntervalSeconds
  );
  event PriceUpdated(uint80 roundId, int256 answer, uint256 timestamp);

  /**
   * @param initialOwner Address that receives the owner role. Deliberately not
   * derived from the deploying key: a deployment key that is later retired must
   * not inherit any live authority from having run the deployment.
   * @param initialUpdater The only address authorized to publish prices at
   * deployment. It is an independent role, so the owner does NOT become an
   * updater here.
   * @param initialAnswer First round's price, 1e18 scaled. A deployed oracle
   * always carries a readable round, so it can be validated and installed by
   * `Perpetual.setOracle` in the transaction that follows deployment.
   * @param decimals_ Price scaling; see `_decimals`.
   * @param description_ Human-readable feed label.
   * @dev A zero `initialOwner` is rejected by OpenZeppelin's Ownable with
   * `OwnableInvalidOwner`; the zero `initialUpdater` check is ours because the
   * updater role is defined by this contract.
   */
  constructor(
    address initialOwner,
    address initialUpdater,
    int256 initialAnswer,
    uint8 decimals_,
    string memory description_,
    uint128 _maxStalenessSeconds,
    uint128 _maxUpdateBps,
    uint128 _minUpdateIntervalSeconds
  ) Ownable(initialOwner) {
    require(bytes(description_).length > 0, 'IBPO: description is empty');
    _decimals = decimals_;
    _description = description_;
    maxStalenessSeconds = _maxStalenessSeconds;
    maxUpdateBps = _maxUpdateBps;
    minUpdateIntervalSeconds = _minUpdateIntervalSeconds;
    emit ConfigSet(
      _maxStalenessSeconds,
      _maxUpdateBps,
      _minUpdateIntervalSeconds
    );

    _validateAnswer(initialAnswer);
    _setUpdater(initialUpdater, true);
    _writeNewRound(initialAnswer);
  }

  // Admin

  /// @notice Grant or revoke one updater without touching the others. Use this
  /// to add a replacement publisher alongside the incumbent so the new lane can
  /// be verified before `rotateUpdater` retires the old key.
  function setUpdater(address account, bool isAuthorized) external onlyOwner {
    _setUpdater(account, isAuthorized);
  }

  /**
   * @notice Atomically retire one updater and authorize its replacement, so a
   * handoff can never leave the retired key authorized or the oracle without a
   * publisher.
   * @param retiredUpdater Currently authorized updater to revoke.
   * @param newUpdater Replacement updater to authorize.
   */
  function rotateUpdater(
    address retiredUpdater,
    address newUpdater
  ) external onlyOwner {
    // A retired address that is not currently authorized means the caller's
    // view of the live role set is wrong; fail instead of emitting handoff
    // evidence for a rotation that did not happen. This also rejects the zero
    // address, which can never be an updater.
    require(updaters[retiredUpdater], 'IBPO: retired not updater');
    require(retiredUpdater != newUpdater, 'IBPO: rotation to same updater');
    _setUpdater(retiredUpdater, false);
    _setUpdater(newUpdater, true);
    emit UpdaterRotated(retiredUpdater, newUpdater);
  }

  /**
   * @notice Disabled. This oracle must always have an owner.
   * @dev Renouncing would freeze the updater set forever: no key could be
   * granted or revoked again. Above all, `updaters` is not enumerable, so a
   * retired key that is still authorized at renunciation could never be
   * revoked by anyone. Blocking only the case where the owner is itself an
   * updater would not cover that: once ownership moves to a Safe — or simply
   * once the deployment key's updater bit is retired — the owner stops being
   * an updater and such a guard passes while the real hazard remains.
   * Ownership still moves normally through `transferOwnership` /
   * `acceptOwnership`.
   */
  function renounceOwnership() public pure override {
    revert('IBPO: ownership cannot be renounced');
  }

  function _setUpdater(address account, bool isAuthorized) private {
    require(account != address(0), 'IBPO: updater is zero');
    updaters[account] = isAuthorized;
    emit UpdaterSet(account, isAuthorized);
  }

  // Updater
  function setPrice(int256 newAnswer) external virtual {
    require(updaters[_msgSender()], 'IBPO: not updater');
    _validateAnswer(newAnswer);
    // percent-change cap (if enabled)
    if (maxUpdateBps > 0 && _latestRound > 0) {
      int256 prev = _answers[_latestRound];
      if (prev != 0) {
        int256 diff = newAnswer - prev;
        if (diff < 0) diff = -diff;
        require(
          uint256(int256(diff)) * 10000 <=
            uint256(int256(prev < 0 ? -prev : prev)) * maxUpdateBps,
          'IBPO: change too large'
        );
      }
    }
    _writeNewRound(newAnswer);
  }

  function _validateAnswer(int256 answer) internal pure {
    require(answer > 0, 'IBPO: price must be > 0');
    require(uint256(answer) <= type(uint128).max, 'IBPO: price exceeds uint128');
  }

  /// @dev The single writer for round state. `startedAt` and `updatedAt` are
  /// both `block.timestamp` and are never taken from a caller — this is the
  /// structural reason a future-dated round cannot exist on this feed.
  function _writeNewRound(int256 answer) internal {
    require(
      _latestRound == 0 || lastUpdateBlock < block.number,
      'IBPO: already updated this block'
    );
    if (minUpdateIntervalSeconds > 0 && _latestRound > 0) {
      require(
        block.timestamp >= _updatedAt[_latestRound] + minUpdateIntervalSeconds,
        'IBPO: update too soon'
      );
    }
    _latestRound += 1;
    lastUpdateBlock = block.number;
    _answers[_latestRound] = answer; // expected to be 1e18 scaled
    _startedAt[_latestRound] = block.timestamp;
    _updatedAt[_latestRound] = block.timestamp;
    emit PriceUpdated(_latestRound, answer, block.timestamp);
  }

  // AggregatorV3Interface
  function decimals() external view override returns (uint8) {
    return _decimals;
  }

  function description() external view override returns (string memory) {
    return _description;
  }

  function latestRoundData()
    external
    view
    override
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    )
  {
    roundId = _latestRound;
    answer = _answers[_latestRound];
    startedAt = _startedAt[_latestRound];
    updatedAt = _updatedAt[_latestRound];
    answeredInRound = _latestRound;
  }

  function getRoundData(
    uint80 _roundId
  )
    external
    view
    override
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    )
  {
    // Match AggregatorV3 semantics: revert on rounds that were never written
    // (round 0 or any round past the latest) instead of returning a zero answer
    // a consumer could misread as a real price.
    require(_roundId != 0 && _roundId <= _latestRound, 'IBPO: No data present');
    roundId = _roundId;
    answer = _answers[_roundId];
    startedAt = _startedAt[_roundId];
    updatedAt = _updatedAt[_roundId];
    answeredInRound = _roundId;
  }
}
