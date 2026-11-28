from mandit.safety.site_scan.html_checks import extract_page_structure

PAGE = "https://shop.example/checkout"


def test_relative_action_resolves_against_page():
    page = extract_page_structure('<form action="/pay"><input name="cvv"></form>', PAGE)
    assert page.payment_forms[0].action_url == "https://shop.example/pay"


def test_missing_action_posts_to_the_page_itself():
    page = extract_page_structure('<form><input autocomplete="cc-number"></form>', PAGE)
    assert page.payment_forms[0].action_url == PAGE


def test_base_href_redirects_relative_action():
    html = '<base href="https://evil.example/"><form action="pay"><input name="cvv"></form>'
    assert (
        extract_page_structure(html, PAGE).payment_forms[0].action_url == "https://evil.example/pay"
    )


def test_non_payment_forms_are_ignored():
    html = '<form action="https://search.example/"><input name="q"><button>Search</button></form>'
    page = extract_page_structure(html, PAGE)
    assert page.forms and not page.payment_forms


def test_button_text_marks_payment_form():
    html = '<form action="https://x.example/go"><input name="n"><button>Pay now</button></form>'
    assert extract_page_structure(html, PAGE).payment_forms


def test_upi_vpas_found_in_links_scripts_and_inputs():
    html = (
        '<a href="upi://pay?pa=a.one@bank&amp;am=1">x</a>'
        '<script>location="upi://pay?pa=b.two@bank&am=2"</script>'
        '<form><input type="hidden" name="vpa" value="c.three@bank"><button>Pay</button></form>'
    )
    assert extract_page_structure(html, PAGE).all_vpas == [
        "a.one@bank",
        "b.two@bank",
        "c.three@bank",
    ]


def test_payment_iframes_flagged_others_not():
    html = (
        '<iframe src="https://pay.psp.example/card-frame"></iframe>'
        '<iframe src="https://video.example/embed/1" title="Product video"></iframe>'
    )
    frames = extract_page_structure(html, PAGE).frames
    assert [f.is_payment for f in frames] == [True, False]
