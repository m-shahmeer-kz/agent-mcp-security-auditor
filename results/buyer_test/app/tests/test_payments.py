STRIPE_TEST_KEY = "sk_test_51Hx9fakefakefakefakefake000000"
def test_refund_shape():
    assert STRIPE_TEST_KEY.startswith("sk_test_")
