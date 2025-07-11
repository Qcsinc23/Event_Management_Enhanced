import requests

# Test API endpoint
url = "http://127.0.0.1:5000/api/events"
params = {
    "start": "2025-06-30T00:00:00-04:00",
    "end": "2025-08-11T00:00:00-04:00",
    "categories": "1,2,3",
    "statuses": "booked,confirmed,in_progress,completed"
}

# Make request without authentication to see what happens
response = requests.get(url, params=params)
print(f"Without auth - Status: {response.status_code}")
print(f"Response: {response.text[:200] if response.text else 'No content'}")

# Test without category filter
params2 = {
    "start": "2025-06-30T00:00:00-04:00",
    "end": "2025-08-11T00:00:00-04:00",
    "statuses": "booked"
}
response2 = requests.get(url, params=params2)
print(f"\nWithout categories - Status: {response2.status_code}")
print(f"Response: {response2.text[:200] if response2.text else 'No content'}")
