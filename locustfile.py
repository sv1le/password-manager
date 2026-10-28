from locust import HttpUser, task, between
import random

class PasswordManagerUser(HttpUser):
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks

    def on_start(self):
        """Runs once when each simulated user starts."""
        self.email = f"loadtest_{random.randint(100000, 999999)}@test.com"
        self.password = "TestPassword123"

    @task(3)
    def health_check(self):
        """Simulate health check requests — most common."""
        self.client.get("/api/health")

    @task(2)
    def register_user(self):
        """Simulate user registration."""
        self.client.post("/api/register", json={
            "email": self.email,
            "password": self.password
        })

    @task(2)
    def login_user(self):
        """Simulate user login (may fail if user doesn't exist — that's fine)."""
        self.client.post("/api/login", json={
            "email": self.email,
            "password": self.password
        })