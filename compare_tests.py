import generic_test
import test_ed25519
import test_nacl

if __name__ == '__main__':
    quantity = 5000
    msg_size = 48
    times_sgn_ed25519, times_vrf_ed25519 = generic_test.test_sign_verify_times(test_ed25519.keypair_generator, test_ed25519.sign_message, test_ed25519.verify_message, quantity, msg_size)
    times_sgn_nacl, times_vrf_nacl = generic_test.test_sign_verify_times(test_nacl.keypair_generator, test_nacl.sign_message, test_nacl.verify_message, quantity, msg_size)
    gbl_sgn_ed, gbl_ver_ed, avg_sgn_ed, avg_ver_ed, avg_both_ed, max_sgn_ed, max_ver_ed = generic_test.test_statistics("ed25519", times_sgn_ed25519, times_vrf_ed25519)
    gbl_sgn_nacl, gbl_ver_nacl, avg_sgn_nacl, avg_ver_nacl, avg_both_nacl, max_sgn_nacl, max_ver_nacl = generic_test.test_statistics("nacl", times_sgn_nacl, times_vrf_nacl)
    