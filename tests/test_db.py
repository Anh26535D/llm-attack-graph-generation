from crystalball.db import Database


def test_store_and_fetch_cve(tmp_path):
    db = Database(tmp_path / "test.sqlite3")
    db.store_cve("CVE-2020-1885", "Some description", "PUBLISHED")

    assert db.cve_exists("CVE-2020-1885")
    assert db.count_cves() == 1

    descriptions = db.get_cve_descriptions({"CVE-2020-1885"})
    assert descriptions == {"CVE-2020-1885": "Some description"}


def test_product_and_version_roundtrip(tmp_path):
    db = Database(tmp_path / "test.sqlite3")
    db.store_cve("CVE-2020-1885", "desc", "PUBLISHED")
    product_id = db.store_product("CVE-2020-1885", "Oculus Desktop", "vecfile.npy")
    db.store_version(product_id, "1.44.0.32849", "<")

    products = db.all_products()
    assert len(products) == 1
    assert products[0].product_name == "Oculus Desktop"


def test_delete_cve_cascades(tmp_path):
    db = Database(tmp_path / "test.sqlite3")
    db.store_cve("CVE-X", "desc", "PUBLISHED")
    db.store_product("CVE-X", "Product", "vecfile.npy")
    db.store_platform("CVE-X", "Windows", "vecfile2.npy")

    db.delete_cve("CVE-X")

    assert not db.cve_exists("CVE-X")
    assert db.all_products() == []
    assert db.all_platforms() == []
