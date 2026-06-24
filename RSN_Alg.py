import math
import secrets
import re

# ============================================================
# RSN ALGORITHM PARAMETERS
# ============================================================

P = 2**61 - 1
PHI = P - 1
G = 37
BASE_TEXT = 29
BASE_VECTOR = 65537
ROUNDS = 16

CHARSET = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ") + [" ", ".", "?"]
CHAR_TO_NUM = {c: i for i, c in enumerate(CHARSET)}
NUM_TO_CHAR = {i: c for c, i in CHAR_TO_NUM.items()}

DIGIT_WORDS = {
    "0": "ZERO",
    "1": "ONE",
    "2": "TWO",
    "3": "THREE",
    "4": "FOUR",
    "5": "FIVE",
    "6": "SIX",
    "7": "SEVEN",
    "8": "EIGHT",
    "9": "NINE",
}


# ============================================================
# TEXT PREPARATION
# ============================================================

def normalize_supported_text(text):
    """
    Converts input into RSN-supported characters.
    Digits are replaced with words so the original base-29 design remains unchanged.
    """
    output = []

    for c in text.upper():
        if c.isdigit():
            output.append(" " + DIGIT_WORDS[c] + " ")
        elif c in CHAR_TO_NUM:
            output.append(c)
        else:
            output.append(" ")

    cleaned = "".join(output)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    cleaned = re.sub(r"\s+([.?])", r"\1", cleaned)

    return cleaned


def prepare_plaintext(plaintext):
    cleaned = normalize_supported_text(plaintext)

    if not cleaned:
        raise ValueError("Plaintext cannot be empty after preparation.")

    original_length = len(cleaned)

    while len(cleaned) % 24 != 0:
        cleaned += "?"

    return cleaned, original_length


# ============================================================
# BASE CONVERSION FUNCTIONS
# ============================================================

def pack_base(digits, base):
    value = 0

    for digit in digits:
        value = value * base + digit

    return value


def split_base(value, base, length):
    digits = [0] * length

    for i in range(length - 1, -1, -1):
        digits[i] = value % base
        value //= base

    return digits


def pack_text_12(text):
    nums = [CHAR_TO_NUM[c] for c in text]
    return pack_base(nums, BASE_TEXT)


def unpack_text_12(value):
    nums = split_base(value, BASE_TEXT, 12)
    return "".join(NUM_TO_CHAR[n] for n in nums)


# ============================================================
# DIRECT SECRET KEY SEED
# ============================================================

def text_seed(secret_key):
    """
    Used only if the channel is secure.
    Converts the shared text key into a numeric seed.
    """
    cleaned_key = normalize_supported_text(secret_key)

    if not cleaned_key:
        raise ValueError("Secret key cannot be empty.")

    values = [CHAR_TO_NUM[c] for c in cleaned_key]

    seed = 0

    for i, value in enumerate(values):
        seed += (i + 1) * value

    return seed % PHI


# ============================================================
# KEY SHARING PROCESS
# ============================================================

def generate_private_lock():
    """
    Generates a private exponent that is relatively prime to PHI.
    This allows a modular inverse to exist.
    """
    while True:
        value = secrets.randbelow(PHI - 3) + 2

        if math.gcd(value, PHI) == 1:
            return value


def key_sharing_process():
    """
    Three-pass key sharing process.
    This is used only when the channel is not secure.
    """

    print("\n================ KEY SHARING PROCESS ================")
    print("The channel is not secure, so RSN will use the key-sharing process.\n")

    print("Public values:")
    print("P =", P)
    print("Euler Totient φ(P) = P - 1 =", PHI)

    choice = input("\nEnter numeric session key S or press Enter to generate randomly: ").strip()

    if choice:
        S = int(choice)

        if not (1 < S < P):
            raise ValueError("S must be greater than 1 and less than P.")
    else:
        S = secrets.randbelow(P - 3) + 2

    print("\nAlice selects session key:")
    print("S =", S)

    a = generate_private_lock()
    a_inverse = pow(a, -1, PHI)

    print("\nAlice chooses private lock:")
    print("a =", a)
    print("Alice's unlock value a_inverse =", a_inverse)

    X = pow(S, a, P)

    print("\nStep 1: Alice locks the session key")
    print("Alice sends X = S^a mod P")
    print("X =", X)

    b = generate_private_lock()
    b_inverse = pow(b, -1, PHI)

    print("\nBob chooses private lock:")
    print("b =", b)
    print("Bob's unlock value b_inverse =", b_inverse)

    Y = pow(X, b, P)

    print("\nStep 2: Bob adds his lock")
    print("Bob sends Y = X^b mod P")
    print("Y =", Y)

    Z = pow(Y, a_inverse, P)

    print("\nStep 3: Alice removes her lock")
    print("Alice sends Z = Y^a_inverse mod P")
    print("Z =", Z)

    recovered_S = pow(Z, b_inverse, P)

    print("\nStep 4: Bob removes his lock")
    print("Bob recovers S = Z^b_inverse mod P")
    print("Recovered S =", recovered_S)

    if recovered_S == S:
        print("\nKey sharing successful.")
        print("Alice and Bob now share the same session key.")
    else:
        raise ValueError("Key sharing failed.")

    print("\nThis recovered S will now be used as the RSN master seed.")
    print("=====================================================\n")

    return recovered_S


# ============================================================
# MATRIX FUNCTIONS
# ============================================================

def determinant_mod(matrix, mod):
    """
    Calculates determinant modulo mod.
    Used to check whether the matrix is valid for Hill-style diffusion.
    """
    n = len(matrix)
    temp = [row[:] for row in matrix]
    determinant = 1

    for i in range(n):
        pivot = None

        for r in range(i, n):
            if temp[r][i] % mod != 0:
                pivot = r
                break

        if pivot is None:
            return 0

        if pivot != i:
            temp[i], temp[pivot] = temp[pivot], temp[i]
            determinant = (-determinant) % mod

        pivot_value = temp[i][i] % mod
        determinant = (determinant * pivot_value) % mod
        inverse = pow(pivot_value, -1, mod)

        for r in range(i + 1, n):
            factor = (temp[r][i] * inverse) % mod

            for c in range(i, n):
                temp[r][c] = (temp[r][c] - factor * temp[i][c]) % mod

    return determinant % mod


def generate_matrix(seed, round_number):
    """
    Generates a key-dependent and round-dependent 4x4 matrix.
    """
    matrix = []

    for i in range(4):
        row = []

        for j in range(4):
            value = pow(
                G,
                seed + 31 * round_number + 4 * i + j + 1,
                P
            ) % BASE_VECTOR

            row.append(value)

        matrix.append(row)

    counter = 0

    while determinant_mod(matrix, BASE_VECTOR) == 0:
        for i in range(4):
            matrix[i][i] = (matrix[i][i] + 1 + counter) % BASE_VECTOR

        counter += 1

    return matrix


def matrix_vector_multiply(matrix, vector, mod):
    result = []

    for i in range(4):
        total = 0

        for j in range(4):
            total += matrix[i][j] * vector[j]

        result.append(total % mod)

    return result


# ============================================================
# ROUND KEY AND PERMUTATION GENERATION
# ============================================================

def generate_round_key(seed, round_number):
    return pow(G, seed + round_number, P)


def generate_permutation(seed, round_number):
    """
    Generates a key-based permutation.
    It is not random; the same seed and round number always produce the same permutation.
    """
    scores = []

    for i in range(4):
        score = pow(G, seed + 13 * round_number + i, P) % BASE_VECTOR
        scores.append((i, score))

    scores.sort(key=lambda x: (x[1], x[0]))

    return [position for position, score in scores]


# ============================================================
# ROUND FUNCTION
# ============================================================

def round_function(right, seed, round_number, trace=False):
    round_key = generate_round_key(seed, round_number)

    T = (right + round_key) % P

    U = pow(G, T, P)

    split_vector = split_base(U, BASE_VECTOR, 4)

    matrix = generate_matrix(seed, round_number)
    determinant = determinant_mod(matrix, BASE_VECTOR)

    mixed_vector = matrix_vector_multiply(matrix, split_vector, BASE_VECTOR)

    permutation = generate_permutation(seed, round_number)

    permuted_vector = [mixed_vector[i] for i in permutation]

    F_output = pack_base(permuted_vector, BASE_VECTOR) % P

    if trace:
        return F_output, {
            "round": round_number,
            "right_input": right,
            "round_key": round_key,
            "T": T,
            "U": U,
            "split_vector": split_vector,
            "matrix": matrix,
            "determinant": determinant,
            "mixed_vector": mixed_vector,
            "permutation": permutation,
            "permuted_vector": permuted_vector,
            "F_output": F_output,
        }

    return F_output


# ============================================================
# ENCRYPTION AND DECRYPTION
# ============================================================

def encrypt_block(left, right, seed, show_first_two_rounds=False):
    round_traces = []

    for round_number in range(1, ROUNDS + 1):
        if show_first_two_rounds and round_number in [1, 2]:
            F_output, trace_data = round_function(
                right,
                seed,
                round_number,
                trace=True
            )
        else:
            F_output = round_function(right, seed, round_number)
            trace_data = None

        new_left = right
        new_right = (left + F_output) % P

        if trace_data is not None:
            trace_data["left_input"] = left
            trace_data["new_left"] = new_left
            trace_data["new_right"] = new_right
            round_traces.append(trace_data)

        left, right = new_left, new_right

    return left, right, round_traces


def decrypt_block(left, right, seed):
    for round_number in range(ROUNDS, 0, -1):
        old_right = left
        F_output = round_function(old_right, seed, round_number)
        old_left = (right - F_output) % P

        left, right = old_left, old_right

    return left, right


def encrypt_message(plaintext, seed):
    prepared_text, original_length = prepare_plaintext(plaintext)

    ciphertext_blocks = []
    first_block_traces = []

    for i in range(0, len(prepared_text), 24):
        block = prepared_text[i:i + 24]

        left_text = block[:12]
        right_text = block[12:]

        left = pack_text_12(left_text)
        right = pack_text_12(right_text)

        show_trace = i == 0

        encrypted_left, encrypted_right, traces = encrypt_block(
            left,
            right,
            seed,
            show_first_two_rounds=show_trace
        )

        ciphertext_blocks.append((encrypted_left, encrypted_right))

        if show_trace:
            first_block_traces = traces

    return ciphertext_blocks, original_length, prepared_text, first_block_traces


def decrypt_message(ciphertext_blocks, seed, original_length):
    plaintext = ""

    for left, right in ciphertext_blocks:
        decrypted_left, decrypted_right = decrypt_block(left, right, seed)

        plaintext += unpack_text_12(decrypted_left)
        plaintext += unpack_text_12(decrypted_right)

    return plaintext[:original_length]


# ============================================================
# OUTPUT FORMATTING
# ============================================================

def ciphertext_to_hex(ciphertext_blocks):
    output = []

    for left, right in ciphertext_blocks:
        output.append(f"{left:016x}-{right:016x}")

    return " | ".join(output)


def print_matrix(matrix):
    for row in matrix:
        print(row)


def print_round_trace(trace):
    print(f"\n================ ROUND {trace['round']} DETAILS ================")

    print("Left input:")
    print(trace["left_input"])

    print("\nRight input:")
    print(trace["right_input"])

    print("\nRound key:")
    print(trace["round_key"])

    print("\nAfter key mixing, T:")
    print(trace["T"])

    print("\nAfter primitive-root substitution, U:")
    print(trace["U"])

    print("\nU split into 4 values using base 65537:")
    print(trace["split_vector"])

    print("\nRound matrix:")
    print_matrix(trace["matrix"])

    print("\nDeterminant mod 65537:")
    print(trace["determinant"])

    print("\nAfter matrix diffusion:")
    print(trace["mixed_vector"])

    print("\nKey-based permutation:")
    print(trace["permutation"])

    print("\nAfter permutation:")
    print(trace["permuted_vector"])

    print("\nRound function output F:")
    print(trace["F_output"])

    print("\nNew left:")
    print(trace["new_left"])

    print("\nNew right:")
    print(trace["new_right"])

    print("=====================================================")


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():
    print("=====================================================")
    print("RSN Algorithm Implementation")
    print("Symmetric Encryption with Key Sharing")
    print("Made By Nehan Shah")
    print("=====================================================")

    plaintext = input("\nEnter plaintext: ")

    secure_channel = input(
        "\nIs the channel secure for sharing the secret key? (yes/no): "
    ).strip().lower()

    if secure_channel in ["yes", "y"]:
        print("\nSecure channel selected.")
        print("The RSN secret key will be shared directly and converted into a seed.")

        secret_key = input("\nEnter RSN secret key: ")
        seed = text_seed(secret_key)

        print("\nGenerated RSN seed from secret key:")
        print(seed)

    else:
        seed = key_sharing_process()

    ciphertext_blocks, original_length, prepared_text, round_traces = encrypt_message(
        plaintext,
        seed
    )

    print("\n================ PLAINTEXT PREPARATION ================")
    print("Prepared plaintext:")
    print(prepared_text)
    print("Original prepared length before padding:")
    print(original_length)
    print("=======================================================")

    print("\nShowing Round 1 and Round 2 details for the first plaintext block only.")

    for trace in round_traces:
        print_round_trace(trace)

    final_ciphertext = ciphertext_to_hex(ciphertext_blocks)

    print("\n================ FINAL ENCRYPTED TEXT ================")
    print(final_ciphertext)
    print("======================================================")

    decrypted_text = decrypt_message(ciphertext_blocks, seed, original_length)

    print("\n================ DECRYPTION CHECK ================")
    print("Decrypted text:")
    print(decrypted_text)
    print("==================================================")


if __name__ == "__main__":
    main()