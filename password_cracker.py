import hashlib

def crack_sha1_hash(hash, use_salts = False):
    with open('top-10000-passwords.txt') as top_pass_f:
        for line in top_pass_f:
            p = line.strip()
            res = False
            if (use_salts):
                res = execute_hash_comparison_with_salts(hash, p);
            else:
                res = execute_hash_comparison(hash, p)
            if (res):
                return p
    return "PASSWORD NOT IN DATABASE"

def execute_hash_comparison_with_salts(hash, password):
    with open('known-salts.txt') as known_salts_f:
        for line in known_salts_f:
            s = line.strip()
            # append salt
            salted_password = password + s
            res = execute_hash_comparison(hash, salted_password)
            if (res):
                return res

            # prepend salt
            salted_password = s + password
            res = execute_hash_comparison(hash, salted_password)
            if (res):
                return res
    return False


def execute_hash_comparison(hash, password):
    hashed_p = hashlib.sha1(password.encode()).hexdigest()
    if (hash == hashed_p):
        return True
    return False