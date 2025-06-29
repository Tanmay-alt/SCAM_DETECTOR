# tests/test_unit.py

import pytest
from app import categorize_risk, categorize_site_risk

def test_categorize_risk():
    """
    Tests the main risk categorization function.
    """
    assert categorize_risk(0.90) == 'High Risk'
    assert categorize_risk(0.85) == 'Medium Risk' # Note: your function is > 0.85 for High
    assert categorize_risk(0.70) == 'Medium Risk'
    assert categorize_risk(0.60) == 'Low Risk'    # Note: your function is > 0.60 for Medium
    assert categorize_risk(0.10) == 'Low Risk'

def test_categorize_site_risk():
    """
    Tests the website-specific risk categorization function.
    """
    assert categorize_site_risk(0.80) == 'High Risk'
    assert categorize_site_risk(0.75) == 'High Risk'
    assert categorize_site_risk(0.60) == 'Medium Risk'
    assert categorize_site_risk(0.50) == 'Medium Risk'
    assert categorize_site_risk(0.40) == 'Low Risk'