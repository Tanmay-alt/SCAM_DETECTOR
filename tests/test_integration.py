# tests/test_integration.py (Updated)

def test_login_page(client):
    """
    Tests that the login page loads correctly with a GET request.
    """
    response = client.get('/login')
    assert response.status_code == 200
    # UPDATED: Check for text that exists on the new login page.
    assert b"Don't have an account?" in response.data
    assert b"Register here" in response.data

def test_main_analyzer_redirects(client):
    """
    Tests that accessing the main analyzer page without being logged in
    redirects the user to the login page.
    """
    # The follow_redirects=True tells the test client to follow the redirect to the login page
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200
    # UPDATED: After redirect, we should be on the login page, so we check for its content.
    assert b"Don't have an account?" in response.data
    assert b"Register here" in response.data