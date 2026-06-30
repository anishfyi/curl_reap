from curl_reap import Geocoder


def test_clean_name_strips_generic_suffix():
    g = Geocoder()
    assert g.clean_name("Chelsea Cloisters Serviced Apartments") == "Chelsea Cloisters"
    assert g.clean_name("Citadines Islington London Aparthotel") == "Citadines Islington London"
    assert g.clean_name("Red Lion Court by City2Stay") == "Red Lion Court"
    # a real place name with no generic descriptor is left intact
    assert g.clean_name("Cleveland Residences Bloomsbury") == "Cleveland Residences Bloomsbury"


def test_candidate_cascade_order_and_cleaning():
    g = Geocoder()
    cands = g._candidates("Chelsea Cloisters Serviced Apartments", "Kensington", "London", "United Kingdom")
    precisions = [p for p, _ in cands]
    # specific name queries first, city centroid last
    assert precisions[0] == "name"
    assert precisions[-1] == "city"
    # a cleaned variant (without the generic suffix) is among the candidates
    assert any("Chelsea Cloisters," in q and "Apartments" not in q for _, q in cands)
    # district fallback exists between name and city
    assert "district" in precisions


def test_candidates_dedup_and_minimal_inputs():
    g = Geocoder()
    assert g._candidates(None, None, "London", "United Kingdom") == [("city", "London, United Kingdom")]
    # no inputs -> no candidates
    assert g._candidates(None, None, None, None) == []
