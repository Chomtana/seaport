// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import { EIP1271Interface } from "contracts/interfaces/EIP1271Interface.sol";

// prettier-ignore
import {
    SignatureVerificationErrors
} from "contracts/interfaces/SignatureVerificationErrors.sol";

import "contracts/lib/ConsiderationConstants.sol";

/**
 * @title SignatureVerification
 * @author 0age
 * @notice SignatureVerification contains logic for verifying signatures.
 */
contract ReferenceSignatureVerification is SignatureVerificationErrors {
    /**
     * @dev Internal view function to verify the signature of an order. An
     *      ERC-1271 fallback will be attempted if either the signature length
     *      is not 32 or 33 bytes or if the recovered signer does not match the
     *      supplied signer.
     *
     * @param signer    The signer for the order.
     * @param digest    The digest to verify the signature against.
     * @param signature A signature from the signer indicating that the order
     *                  has been approved.
     */
    function _assertValidSignature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal view {
        // Declare r, s, and v signature parameters.
        bytes32 r;
        bytes32 s;
        uint8 v;

        // If signature contains 64 bytes, parse as EIP-2098 signature. (r+s&v)
        if (signature.length == 64) {
            // Declare temporary vs that will be decomposed into s and v.
            bytes32 vs;

            (r, vs) = abi.decode(signature, (bytes32, bytes32));

            s = vs & EIP2098_allButHighestBitMask;

            v = uint8(uint256(vs >> 255)) + 27;
        } else if (signature.length == 65) {
            (r, s) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(signature[64]);

            // Ensure v value is properly formatted.
            if (v != 27 && v != 28) {
                // Revert with BadSignatureV(v) and passed the error to EIP-1271 signature verification.
                bytes memory errorSignature = abi.encodeWithSignature("BadSignatureV(uint8)", v);
                _assertValidEIP1271Signature(signer, digest, errorSignature.length, errorSignature, signature);
            }
        } else {
            // For all other signature lengths, try verification via EIP-1271.
            // Attempt EIP-1271 static call to signer in case it's a contract.
            _assertValidEIP1271Signature(signer, digest, 0, "", signature);

            // Return early if the ERC-1271 signature check succeeded.
            return;
        }

        // Attempt to recover signer using the digest and signature parameters.
        address recoveredSigner = ecrecover(digest, v, r, s);

        // Disallow invalid signers.
        if (recoveredSigner == address(0)) {
            // Revert with InvalidSignature and passed the error to EIP-1271 signature verification.
            bytes memory errorSignature = abi.encodeWithSignature("InvalidSignature()");
            _assertValidEIP1271Signature(signer, digest, errorSignature.length, errorSignature, signature);
            
            // Should a signer be recovered, but it doesn't match the signer...
        } else if (recoveredSigner != signer) {
            // Attempt EIP-1271 static call to signer in case it's a contract.
            _assertValidEIP1271Signature(signer, digest, 0, "", signature);
        }
    }

    /**
     * @dev Internal view function to verify the signature of an order using
     *      ERC-1271 (i.e. contract signatures via `isValidSignature`).
     *
     * @param signer    The signer for the order.
     * @param digest    The signature digest, derived from the domain separator
     *                  and the order hash.
     * @param signature A signature (or other data) used to validate the digest.
     */
    function _assertValidEIP1271Signature(
        address signer,
        bytes32 digest,
        uint256 errorLength,
        bytes memory errorSignature,
        bytes memory signature
    ) internal view {
        bool isEOA;
        assembly {
            isEOA := iszero(extcodesize(signer))
        }

        if (isEOA) {
            if (errorLength == 0) {
                // If error is not passed from _assertValidSignature, revert with InvalidSigner().
                revert InvalidSigner();
            } else {
                // If error is passed from _assertValidSignature, revert with passed error.
                assembly {
                    mstore(0, mload(add(errorSignature, 0x20)))
                    mstore(0x04, mload(add(errorSignature, 0x24)))
                    revert(0, errorLength)
                }
            }
        }

        if (
            EIP1271Interface(signer).isValidSignature(digest, signature) !=
            EIP1271Interface.isValidSignature.selector
        ) {
            if (errorLength == 0) {
                // If error is not passed from _assertValidSignature, revert with InvalidSigner().
                revert InvalidSigner();
            } else {
                // If error is passed from _assertValidSignature, revert with passed error.
                assembly {
                    mstore(0, mload(add(errorSignature, 0x20)))
                    mstore(0x04, mload(add(errorSignature, 0x24)))
                    revert(0, errorLength)
                }
            }
        }
    }
}
