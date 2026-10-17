// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.26;

import {ISignatureVerifier} from './interfaces/ISignatureVerifier.sol';
import {TypedSignature} from './libraries/TypedSignature.sol';

/**
 * @title SignatureVerifier
 * @author MNX Markets <help@mnx.fi>
 * @notice Stateless EIP-712 signature verification for margin, leverage, and withdrawal authorizations
 * @dev This contract contains no state - it only performs cryptographic verification.
 *      Nonce management remains in the calling contract for security.
 */
contract SignatureVerifier is ISignatureVerifier {
  /// @dev Hash of the EIP712 MarginAdjustment struct schema
  bytes32 private constant EIP712_MARGIN_STRUCT_SCHEMA_HASH =
    keccak256(
      'MarginAdjustment(address account,uint128 amount,bool isAddition,uint128 nonce)'
    );

  /// @dev Hash of the EIP712 RemoveMarginUpTo struct schema
  bytes32 private constant EIP712_REMOVE_MARGIN_UP_TO_STRUCT_SCHEMA_HASH =
    keccak256(
      'RemoveMarginUpTo(address account,uint128 maxAmount,uint128 minAmount,uint128 nonce)'
    );

  /// @dev Hash of the EIP712 LeverageAdjustment struct schema
  bytes32 private constant EIP712_LEVERAGE_STRUCT_SCHEMA_HASH =
    keccak256(
      'LeverageAdjustment(address account,uint128 leverage,uint128 nonce)'
    );

  /// @dev Hash of the EIP712 Withdraw struct schema
  bytes32 private constant EIP712_WITHDRAW_STRUCT_SCHEMA_HASH =
    keccak256(
      'Withdraw(address owner,address destination,uint128 amount,uint128 minimumAmountOut,uint128 nonce,uint64 deadline)'
    );

  /// @dev EIP712 domain type hash
  bytes32 private constant EIP712_DOMAIN_TYPEHASH =
    keccak256(
      'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
    );

  /// @dev Cached Perpetual name hash for domain separator
  bytes32 private constant PERPETUAL_NAME_HASH = keccak256(bytes('Perpetual'));

  /// @dev Cached MarginBank name hash for domain separator
  bytes32 private constant MARGIN_BANK_NAME_HASH =
    keccak256(bytes('MarginBank'));

  /// @dev Cached version hash for domain separator
  bytes32 private constant VERSION_HASH = keccak256(bytes('1.0'));

  /**
   * @notice Computes the EIP-712 domain separator for a given verifying contract.
   * @param verifyingContract The contract used as verifyingContract in the EIP-712 domain
   * @param nameHash The hashed EIP-712 domain name
   * @return The domain separator hash
   */
  function _computeDomainSeparator(
    address verifyingContract,
    bytes32 nameHash
  ) internal view returns (bytes32) {
    return
      keccak256(
        abi.encode(
          EIP712_DOMAIN_TYPEHASH,
          nameHash,
          VERSION_HASH,
          block.chainid,
          verifyingContract
        )
      );
  }

  /**
   * @inheritdoc ISignatureVerifier
   */
  function recoverMarginSigner(
    address perpetual,
    address account,
    uint128 amount,
    bool isAddition,
    uint128 nonce,
    TypedSignature.Signature calldata signature
  ) external view override returns (address signer) {
    bytes32 domainSeparator = _computeDomainSeparator(
      perpetual,
      PERPETUAL_NAME_HASH
    );

    bytes32 structHash = keccak256(
      abi.encode(
        EIP712_MARGIN_STRUCT_SCHEMA_HASH,
        account,
        amount,
        isAddition,
        nonce
      )
    );

    bytes32 digest = keccak256(
      abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, structHash)
    );

    return TypedSignature.recover(digest, signature);
  }

  /**
   * @inheritdoc ISignatureVerifier
   */
  function recoverRemoveMarginUpToSigner(
    address perpetual,
    address account,
    uint128 maxAmount,
    uint128 minAmount,
    uint128 nonce,
    TypedSignature.Signature calldata signature
  ) external view override returns (address signer) {
    bytes32 domainSeparator = _computeDomainSeparator(
      perpetual,
      PERPETUAL_NAME_HASH
    );

    bytes32 structHash = keccak256(
      abi.encode(
        EIP712_REMOVE_MARGIN_UP_TO_STRUCT_SCHEMA_HASH,
        account,
        maxAmount,
        minAmount,
        nonce
      )
    );

    bytes32 digest = keccak256(
      abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, structHash)
    );

    return TypedSignature.recover(digest, signature);
  }

  /**
   * @inheritdoc ISignatureVerifier
   */
  function recoverLeverageSigner(
    address perpetual,
    address account,
    uint128 leverage,
    uint128 nonce,
    TypedSignature.Signature calldata signature
  ) external view override returns (address signer) {
    bytes32 domainSeparator = _computeDomainSeparator(
      perpetual,
      PERPETUAL_NAME_HASH
    );

    bytes32 structHash = keccak256(
      abi.encode(EIP712_LEVERAGE_STRUCT_SCHEMA_HASH, account, leverage, nonce)
    );

    bytes32 digest = keccak256(
      abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, structHash)
    );

    return TypedSignature.recover(digest, signature);
  }

  /**
   * @inheritdoc ISignatureVerifier
   */
  function recoverWithdrawalSigner(
    address marginBank,
    address owner,
    address destination,
    uint128 amount,
    uint128 minimumAmountOut,
    uint128 nonce,
    uint64 deadline,
    TypedSignature.Signature calldata signature
  ) external view override returns (address signer) {
    bytes32 domainSeparator = _computeDomainSeparator(
      marginBank,
      MARGIN_BANK_NAME_HASH
    );

    bytes32 structHash = keccak256(
      abi.encode(
        EIP712_WITHDRAW_STRUCT_SCHEMA_HASH,
        owner,
        destination,
        amount,
        minimumAmountOut,
        nonce,
        deadline
      )
    );

    bytes32 digest = keccak256(
      abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, structHash)
    );

    return TypedSignature.recover(digest, signature);
  }
}
