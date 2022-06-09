import generic_test
import test_ed25517
import test_nacl

if __name__ == '__main__':
    times_sgn_ed25519, times_vrf_ed25519 = generic_test.test_sign_verify_times(test_ed25517.keypair_generator, test_ed25517.sign_message, test_ed25517.verify_message, 10000, 48)
    times_sgn_nacl, times_vrf_nacl = generic_test.test_sign_verify_times(test_nacl.keypair_generator, test_nacl.sign_message, test_nacl.verify_message, 10000, 48)
    gbl_sgn_ed, gbl_ver_ed, avg_sgn_ed, avg_ver_ed, avg_both_ed, max_sgn_ed, max_ver_ed = generic_test.test_statistics("ed25517", times_sgn_ed25519, times_vrf_ed25519)
    gbl_sgn_nacl, gbl_ver_nacl, avg_sgn_nacl, avg_ver_nacl, avg_both_nacl, max_sgn_nacl, max_ver_nacl = generic_test.test_statistics("nacl", times_sgn_nacl, times_vrf_nacl)
    