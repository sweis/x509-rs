//! Certificate chain building via DFS path finding.
//!
//! Given a leaf certificate and a pool of untrusted intermediates, finds
//! a valid chain that terminates at a trust anchor using depth-first search
//! with backtracking.

use super::TrustStore;
use x509_parser::prelude::*;

/// Maximum chain depth to prevent infinite loops during chain building.
pub(crate) const MAX_CHAIN_DEPTH: usize = 32;

/// Build a certificate chain from leaf to trust anchor using DFS with backtracking.
///
/// Given a leaf certificate and a pool of untrusted intermediates, finds a valid
/// chain that terminates at a trust anchor. Tries multiple paths via backtracking
/// when there are cross-signed or duplicate intermediates.
pub(crate) fn build_chain_dfs(
    leaf_der: &[u8],
    intermediates: &[(Vec<u8>, X509Certificate)],
    trust_store: &TrustStore,
) -> Vec<Vec<u8>> {
    let leaf = match X509Certificate::from_der(leaf_der) {
        Ok((_, cert)) => cert,
        Err(_) => return vec![leaf_der.to_vec()],
    };

    let mut best_chain = vec![leaf_der.to_vec()];
    let mut current_chain = vec![leaf_der.to_vec()];
    let mut used = vec![false; intermediates.len()];

    dfs_build(
        &leaf,
        &mut current_chain,
        &mut used,
        intermediates,
        trust_store,
        &mut best_chain,
    );

    best_chain
}

/// DFS recursive helper for chain building. Returns true if a valid chain
/// terminating at a trust anchor was found.
#[allow(clippy::indexing_slicing)] // used[idx] safe: idx from intermediates.iter().enumerate(), same len
fn dfs_build(
    current: &X509Certificate,
    chain: &mut Vec<Vec<u8>>,
    used: &mut [bool],
    intermediates: &[(Vec<u8>, X509Certificate)],
    trust_store: &TrustStore,
    best: &mut Vec<Vec<u8>>,
) -> bool {
    let issuer_raw = current.issuer().as_raw();

    // Check if current cert is self-signed and in the trust store
    if current.subject().as_raw() == issuer_raw && current.verify_signature(None).is_ok() {
        if let Some(last) = chain.last() {
            if trust_store.contains(last) {
                *best = chain.clone();
                return true;
            }
        }
    }

    // Check if issuer is in the trust store (chain terminates here)
    if let Some(candidates) = trust_store.find_by_subject_raw(issuer_raw) {
        for root_der in candidates {
            if let Ok((_, root)) = X509Certificate::from_der(root_der) {
                if current.verify_signature(Some(root.public_key())).is_ok() {
                    *best = chain.clone();
                    return true;
                }
            }
        }
    }

    // Depth limit
    if chain.len() >= MAX_CHAIN_DEPTH {
        return false;
    }

    // Try each unused intermediate as the next link in the chain
    for (idx, (der, cert)) in intermediates.iter().enumerate() {
        if used[idx] {
            continue;
        }
        if cert.subject().as_raw() != issuer_raw {
            continue;
        }
        // Verify signature from current cert to candidate issuer
        if current.verify_signature(Some(cert.public_key())).is_err() {
            continue;
        }

        used[idx] = true;
        chain.push(der.clone());

        if dfs_build(cert, chain, used, intermediates, trust_store, best) {
            return true;
        }

        chain.pop();
        used[idx] = false;
    }

    false
}
