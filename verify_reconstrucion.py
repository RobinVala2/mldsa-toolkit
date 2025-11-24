import sys
import base64
from pathlib import Path
from dilithium_py.ml_dsa.ml_dsa import ML_DSA
from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS
from dilithium_py.ml_dsa.pkcs import sk_from_pem

captured_intermediates = {}

def sign_with_capture(scheme, sk, m, ctx=b"", deterministic=True):
    """
    Sign a message and capture all intermediate values during signing.
    Wraps _sign_internal from dilithium_py to capture values.
    
    Returns: (signature, captured_intermediates_dict)
    """
    
    global captured_intermediates
    captured_intermediates = {}
    
    original_sign_internal = scheme._sign_internal
    
    def _sign_internal_with_capture(sk_bytes, m_bytes, rnd, external_mu=False):
        rho, k, tr, s1, s2, t0 = scheme._unpack_sk(sk_bytes)
        
        s1_hat = s1.to_ntt()
        s2_hat = s2.to_ntt()
        t0_hat = t0.to_ntt()
        
        A_hat = scheme._expand_matrix_from_seed(rho)
        
        if external_mu:
            mu = m_bytes
        else:
            mu = scheme._h(tr + m_bytes, 64)
        
        rho_prime = scheme._h(k + rnd + mu, 64)
        
        captured_intermediates['mu'] = mu
        captured_intermediates['rho_prime'] = rho_prime
        captured_intermediates['rnd'] = rnd
        
        kappa = 0
        alpha = scheme.gamma_2 << 1
        
        while True:
            y = scheme._expand_mask_vector(rho_prime, kappa)
            y_hat = y.to_ntt()
            w = (A_hat @ y_hat).from_ntt()
            
            kappa += scheme.l
            
            w1 = w.high_bits(alpha)
            
            w1_bytes = w1.bit_pack_w(scheme.gamma_2)
            c_tilde = scheme._h(mu + w1_bytes, scheme.c_tilde_bytes)
            c = scheme.R.sample_in_ball(c_tilde, scheme.tau)
            c_hat = c.to_ntt()

            captured_intermediates['y'] = y
            captured_intermediates['w'] = w
            captured_intermediates['w1'] = w1
            captured_intermediates['c_tilde'] = c_tilde
            captured_intermediates['c'] = c
            
            c_s1 = s1_hat.scale(c_hat).from_ntt()
            z = y + c_s1
            if z.check_norm_bound(scheme.gamma_1 - scheme.beta):
                continue
            
            c_s2 = s2_hat.scale(c_hat).from_ntt()
            r0 = (w - c_s2).low_bits(alpha)
            if r0.check_norm_bound(scheme.gamma_2 - scheme.beta):
                continue
            
            c_t0 = t0_hat.scale(c_hat).from_ntt()
            if c_t0.check_norm_bound(scheme.gamma_2):
                continue
            
            h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
            if h.sum_hint() > scheme.omega:
                continue
            
            captured_intermediates['c_s1'] = c_s1
            captured_intermediates['z'] = z
            captured_intermediates['c_s2'] = c_s2
            captured_intermediates['r0'] = r0
            captured_intermediates['c_t0'] = c_t0
            captured_intermediates['h'] = h
            
            return scheme._pack_sig(c_tilde, z, h)
    
    scheme._sign_internal = _sign_internal_with_capture
    
    try:
        signature = scheme.sign(sk, m, ctx=ctx, deterministic=deterministic)
        return signature, captured_intermediates.copy()
    finally:
        scheme._sign_internal = original_sign_internal

def reconstruct_all_intermediates(scheme, sk, sig, m, ctx=b"", rnd=None, deterministic=True):
    """
    Reconstruct ALL intermediate values from signature and private key.
    1. Extract z, c_tilde, h from signature
    2. Extract s1, s2, t0, tr, rho, k from private key
    3. Compute mu from message
    4. Compute rho_prime (needs rnd, known for deterministic)
    5. Reconstruct c from c_tilde using sample_in_ball (deterministic)
    6. Reconstruct y = z - c·s1
    7. Reconstruct w = Ay (from y)
    8. Reconstruct w1 = high_bits(w)
    9. Reconstruct c·s2, r0, c·t0
    """
    c_tilde, z, h = scheme._unpack_sig(sig)
    rho, k, tr, s1, s2, t0 = scheme._unpack_sk(sk)
    m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m
    mu = scheme._h(tr + m_prime, 64)
    
    if deterministic:
        rnd = bytes([0] * 32)
        rho_prime = scheme._h(k + rnd + mu, 64)
    else:
        if rnd is None:
            print("Need rnd for hedged variant.")
        else:
            print("TBD")
        exit(1)
    

    c = scheme.R.sample_in_ball(c_tilde, scheme.tau)
    
    c_hat = c.to_ntt()
    s1_hat = s1.to_ntt()
    s2_hat = s2.to_ntt()
    t0_hat = t0.to_ntt()
    
    c_s1_hat = s1_hat.scale(c_hat)
    c_s1 = c_s1_hat.from_ntt()

    y = z - c_s1

    A_hat = scheme._expand_matrix_from_seed(rho)
    y_hat = y.to_ntt()
    w = (A_hat @ y_hat).from_ntt()
    
    alpha = scheme.gamma_2 << 1
    w1 = w.high_bits(alpha)
    
    c_s2_hat = s2_hat.scale(c_hat)
    c_s2 = c_s2_hat.from_ntt()
    
    r0 = (w - c_s2).low_bits(alpha)
    
    c_t0_hat = t0_hat.scale(c_hat)
    c_t0 = c_t0_hat.from_ntt()
    
    return {
        'mu': mu,
        'rho_prime': rho_prime,
        'y': y,
        'w': w,
        'w1': w1,
        'c': c,
        'c_tilde': c_tilde,
        'c_s1': c_s1,
        'c_s2': c_s2,
        'r0': r0,
        'c_t0': c_t0,
        'z': z,
        'h': h,
    }

def extract_coefficients(vector, reduce_mod_q=True):
    """
    Extract all coefficients from a vector.
    """
    
    coeffs = []
    m, n = vector.dim()
    q = vector.parent.ring.q
    
    if m >= n:
        for i in range(m):
            poly = vector[i, 0]
            for c in poly.coeffs:
                coeffs.append(c)
    else:
        for j in range(n):
            poly = vector[0, j]
            for c in poly.coeffs:
                coeffs.append(c)
    
    return coeffs

def compare_vectors(captured, reconstructed, reduce_mod_q=True):
    """Compare two vectors and return match status and max difference."""  
    try:
        captured_dim = captured.dim()
        reconstructed_dim = reconstructed.dim()

        # print(f"Captured dimension: {captured_dim}")
        # print(f"Reconstructed dimesnion: {reconstructed_dim}")
        
        captured_vec = captured
        reconstructed_vec = reconstructed
        
        if captured_dim != reconstructed_dim:
            if captured_dim == tuple(reversed(reconstructed_dim)):
                try:
                    captured_vec = captured.T
                    captured_dim = captured_vec.dim()
                except:
                    pass
            elif reconstructed_dim == tuple(reversed(captured_dim)):
                try:
                    reconstructed_vec = reconstructed.T
                    reconstructed_dim = reconstructed_vec.dim()
                except:
                    pass
            
            if captured_dim != reconstructed_dim:
                return False, None, f"Dimension mismatch: {captured.dim()} vs {reconstructed.dim()}"
    except Exception:
        return False, None, "Invalid object type"
    
    try:
        diff = captured_vec - reconstructed_vec
        # print(f"* Difference between the two vectors: {diff}")
        diff_coeffs = extract_coefficients(diff, reduce_mod_q)
        # print(f"* Difference between the coefficients: {diff_coeffs}")
        diff_max = max(abs(c) for c in diff_coeffs) if diff_coeffs else 0
        match = (diff_max == 0)
        
        return match, diff_max, None
    except Exception as e:
        return False, None, f"Comparison error: {str(e)}"

def compare_bytes(captured, reconstructed):
    """Compare two byte arrays."""
    match = (captured == reconstructed)
    return match, None if match else f"Different: captured={captured.hex()[:16]}..., reconstructed={reconstructed.hex()[:16]}..."

def compare_polynomials(captured, reconstructed):
    """Compare two polynomials."""
    captured_coeffs = list(captured.coeffs)
    reconstructed_coeffs = list(reconstructed.coeffs)
    
    if len(captured_coeffs) != len(reconstructed_coeffs):
        return False, f"Different lengths: {len(captured_coeffs)} vs {len(reconstructed_coeffs)}"
    
    diff = [a - b for a, b in zip(captured_coeffs, reconstructed_coeffs)]
    diff_max = max(abs(d) for d in diff)
    match = (diff_max == 0)
    
    return match, None if match else f"Max difference: {diff_max}"

def load_scheme_and_key(param_label):
    """Load scheme and private key from PEM file."""
    key_path = Path(f"mldsa-{param_label}/keys/sk.pem")
    if not key_path.exists():
        raise FileNotFoundError(f"Private key not found: {key_path}")
    
    pem_content = key_path.read_bytes()
    _, sk, _, _ = sk_from_pem(pem_content)

    sk_size = len(sk)

    if sk_size == 2560:
        scheme = ML_DSA(DEFAULT_PARAMETERS["ML_DSA_44"])
        sig_size = 2420
    elif sk_size == 4032:
        scheme = ML_DSA(DEFAULT_PARAMETERS["ML_DSA_65"])
        sig_size = 3309
    elif sk_size == 4896:
        scheme = ML_DSA(DEFAULT_PARAMETERS["ML_DSA_87"])
        sig_size = 4627
    else:
        raise ValueError(f"Unknown key size {sk_size} bytes. Expected 2560 (ML-DSA-44), 4032 (ML-DSA-65), or 4896 (ML-DSA-87)")
    
    return scheme, sk, sig_size
    
def process_one_pair(scheme, sk, message, signature, sample_num):
    print(f"\n[Sample {sample_num}] Processing message/signature pair.")
    
    sig_from_capture, captured = sign_with_capture(scheme, sk, message)
    
    sigs_match = (sig_from_capture == signature)
    if not sigs_match:
        print(f"WARNING: Captured signature doesn't match saved signature!")
    
    reconstructed = reconstruct_all_intermediates(
        scheme, sk, signature, message
    )
    
    comparisons = []
    
    # (not sensitive)
    match, error = compare_bytes(captured.get('mu'), reconstructed.get('mu'))
    comparisons.append(('mu', match, error))
    
    # Private random seed (sensitive)
    match, error = compare_bytes(captured.get('rho_prime'), reconstructed.get('rho_prime'))
    comparisons.append(('rho_prime', match, error))
    
    # Secret polynomial vector (sensitive)
    match, diff_max, error = compare_vectors(captured.get('y'), reconstructed.get('y'), False)
    comparisons.append(('y', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # (sensitive)
    match, diff_max, error = compare_vectors(captured.get('w'), reconstructed.get('w'), False)
    comparisons.append(('w', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # Commitment (not sensitive)
    match, diff_max, error = compare_vectors(captured.get('w1'), reconstructed.get('w1'), False)
    comparisons.append(('w1', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # (not sensitive)
    match, error = compare_polynomials(captured.get('c'), reconstructed.get('c'))
    comparisons.append(('c', match, error))
    
    # Commitment hash (not sensitive)
    match, error = compare_bytes(captured.get('c_tilde'), reconstructed.get('c_tilde'))
    comparisons.append(('c_tilde', match, error))
    
    # Used in computation of signer's response (z = y + cs1) (sensitive)
    match, diff_max, error = compare_vectors(captured.get('c_s1'), reconstructed.get('c_s1'), False)
    comparisons.append(('c_s1', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # Used in computation of r0 (sensitive)
    match, diff_max, error = compare_vectors(captured.get('c_s2'), reconstructed.get('c_s2'), False)
    comparisons.append(('c_s2', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # Used for validity checks (final value not sensitive/intermediate values sensitive)
    match, diff_max, error = compare_vectors(captured.get('r0'), reconstructed.get('r0'), False)
    comparisons.append(('r0', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # Used in hint computation (not sensitive)
    match, diff_max, error = compare_vectors(captured.get('c_t0'), reconstructed.get('c_t0'), False)
    comparisons.append(('c_t0', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # Signer's response (final value not sensitive/intermediate values sensitive)
    match, diff_max, error = compare_vectors(captured.get('z'), reconstructed.get('z'), False)
    comparisons.append(('z', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    # Hint vector (not sensitive)
    match, diff_max, error = compare_vectors(captured.get('h'), reconstructed.get('h'), False)
    comparisons.append(('h', match, error if error else (f"Max diff: {diff_max}" if diff_max else None)))
    
    all_match = all(c[1] for c in comparisons if c[1] is not None)
    match_count = sum(1 for c in comparisons if c[1] is True)
    total_count = sum(1 for c in comparisons if c[1] is not None)
    
    return {
        'all_match': all_match,
        'match_count': match_count,
        'total_count': total_count,
        'comparisons': comparisons,
        'sigs_match': sigs_match
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_reconstrucion.py [44|65|87] [--limit N]")
        sys.exit(1)
    
    param_label = sys.argv[1]
    if param_label not in ['44', '65', '87']:
        print("Error: Parameter set must be 44, 65, or 87")
        sys.exit(1)
    
    limit = None
    if '--limit' in sys.argv:
        idx = sys.argv.index('--limit')
        if idx + 1 < len(sys.argv):
            try:
                limit = int(sys.argv[idx + 1])
            except ValueError:
                print("Error: --limit must be followed by a number")
                sys.exit(1)
    
    print("="*70)
    print(f"ML-DSA-{param_label}: Capture vs Reconstruct Intermediates")
    print("="*70)
    print()
    
    print(f"[1] Loading scheme and private key for ML-DSA-{param_label}.")
    try:
        scheme, sk, sig_size = load_scheme_and_key(param_label)
        print(f"Private key size: {len(sk)} bytes")
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    print()
    
    print("[2] Loading messages from data.bin.")
    data_path = Path("data.bin")
    if not data_path.exists():
        print(f"ERROR: {data_path} not found")
        sys.exit(1)
    
    MSG_SIZE = 32
    messages = []
    with open(data_path, "rb") as f:
        while True:
            msg = f.read(MSG_SIZE)
            if not msg or len(msg) != MSG_SIZE:
                break
            messages.append(msg)
    
    print(f"Loaded {len(messages)} messages")
    print()
    
    print(f"[3] Loading signatures from mldsa-{param_label}/results/signatures.bin...")
    sig_path = Path(f"mldsa-{param_label}/results/signatures.bin")
    if not sig_path.exists():
        print(f"ERROR: {sig_path} not found")
        sys.exit(1)

    signatures = []
    with open(sig_path, "rb") as f:
        while True:
            signature = f.read(sig_size)
            if not signature:
                break
            if len(signature) != sig_size:
                print(f"ERROR: {sig_path} contains incomplete signature: {len(signature)} bytes, expected {sig_size}")
                sys.exit(1)
            signatures.append(signature)
    
    
    print(f"Loaded {len(signatures)} signatures")
    print()
    
    num_pairs = min(len(messages), len(signatures))
    if limit:
        num_pairs = min(num_pairs, limit)
    
    print(f"[4] Processing {num_pairs} message/signature pairs...")
    print()
    
    results = []
    for i in range(num_pairs):
        result = process_one_pair(scheme, sk, messages[i], signatures[i], i + 1)
        results.append(result)
        
        if not result['all_match']:
            print(f"Sample {i + 1}: Some mismatches found")
        else:
            print(f"Sample {i + 1}: All match")
    
    print()
    print("[5] Overall Summary:")
    all_samples_match = all(r['all_match'] for r in results)
    total_match_count = sum(r['match_count'] for r in results)
    total_comparisons = sum(r['total_count'] for r in results)
    
    print(f"Samples processed: {len(results)}")
    print(f"Samples with all matches: {sum(1 for r in results if r['all_match'])}")
    print(f"Samples with mismatches: {sum(1 for r in results if not r['all_match'])}")
    print(f"Total comparisons: {total_comparisons}")
    print(f"Total matches: {total_match_count}")
    print(f"Total mismatches: {total_comparisons - total_match_count}")
    print()
    
    print("="*70)
    if all_samples_match:
        print("All intermediate values match across all samples! Reconstruction is correct.")
    else:
        print("Some intermediate values don't match.")
    print("="*70)

if __name__ == "__main__":
    main()
