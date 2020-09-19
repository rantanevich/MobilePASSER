import unittest
from mobilepass.core import generate_token


class TestMobilePass(unittest.TestCase):
    def test_none_of_policy_and_zero_index(self):
        activation_key = 'QVKYC-FM6KO-SY6F7-TR22W'
        policy = ''
        index = 0
        self.assertEqual(generate_token(
            activation_key=activation_key,
            index=index,
            policy=policy
        ), '374844')

    def test_none_of_policy_and_positive_index(self):
        activation_key = 'QVKYC-FM6KO-SY6F7-TR22W'
        policy = ''
        index = 10
        self.assertEqual(generate_token(
            activation_key=activation_key,
            index=index,
            policy=policy
        ), '690483')

    def test_positive_policy_and_zero_index(self):
        activation_key = 'QVKYC-FM6KO-SY6F7-TR22W'
        policy = '18888710'
        index = 0
        self.assertEqual(generate_token(
            activation_key=activation_key,
            index=index,
            policy=policy
        ), '310551')

    def test_positive_policy_and_positive_index(self):
        activation_key = 'QVKYC-FM6KO-SY6F7-TR22W'
        policy = '18888710'
        index = 10
        self.assertEqual(generate_token(
            activation_key=activation_key,
            index=index,
            policy=policy
        ), '194672')
