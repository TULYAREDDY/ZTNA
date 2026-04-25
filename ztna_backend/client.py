import requests
import time
import random
import datetime

BASE_URL = "http://localhost:8000"   # talks directly to FastAPI backend

def get_current_time_str():
    return datetime.datetime.now().strftime("%H:%M:%S")

class ZTNASimulator:
    def __init__(self):
        self.session_id = None
        self.ip = None
        self.service = "production-db"
        self.request_times = []

    def generate_posture(self):
        """Generates a healthy device posture."""
        return {
            "os":              "Windows",
            "antivirus_active": True,       # matches PostureData model
            "firewall_active":  True,       # matches PostureData model
            "process_count":    random.randint(50, 300),
            "ip_address":       f"192.168.1.{random.randint(10, 200)}"  # matches PostureData model
        }

    def authenticate(self):
        """Step 1: POST to /posture → get session_id."""
        posture = self.generate_posture()
        self.ip = posture["ip_address"]
        try:
            res = requests.post(f"{BASE_URL}/posture", json=posture)
            data = res.json()
            self.session_id = data.get("session_id")

            if self.session_id:
                print("\n===== SESSION CREATED =====")
                print(self.session_id)
                print("==========================\n")
                print(f"[AUTH] {get_current_time_str()} | Session: {self.session_id} | IP: {self.ip} | Risk: {data.get('risk_score')}")
            else:
                print(f"[AUTH] {get_current_time_str()} | Blocked at posture check.")
        except requests.exceptions.ConnectionError:
            print("[ERROR] Cannot connect. Is app.py running on port 8000?")
            exit(1)

    def get_request_rate(self):
        """Requests per second over last 10 seconds."""
        now = time.time()
        recent = [t for t in self.request_times if now - t < 10]
        self.request_times = recent
        rate = len(recent) / 10.0
        return f"{rate:.1f}"

    def simulate_access(self, steal_token=False):
        """Step 2+: POST to /access with same session_id."""
        if not self.session_id:
            return False

        current_ip = self.ip
        if steal_token:
            current_ip = f"10.0.0.{random.randint(1, 255)}"   # different IP = stolen token

        try:
            res = requests.post(f"{BASE_URL}/access", json={
                "session_id":     self.session_id,
                "ip_address":     current_ip,       # matches AccessRequest model
                "target_service": self.service,     # matches AccessRequest model
            })

            self.request_times.append(time.time())
            rate_str = self.get_request_rate()

            if res.status_code == 200:
                data = res.json()
                risk     = data.get("current_risk", "N/A")
                decision = data.get("decision", "ALLOW")
            elif res.status_code == 401:
                decision = "BLOCK (Expired/Invalid)"
                risk     = ">70"
            elif res.status_code == 403:
                decision = "BLOCK (Revoked)"
                risk     = ">70"
            else:
                decision = f"ERROR ({res.status_code})"
                risk     = "N/A"

            status_icon = "✅" if decision == "ALLOW" else "🚫"
            print(f"[LOG] {get_current_time_str()} | session={self.session_id} "
                  f"| ip={current_ip:<15} | rate={rate_str:>3}/s "
                  f"| risk={str(risk):<3} → {status_icon} {decision}")

            return "BLOCK" not in decision

        except Exception as e:
            print(f"[ERROR] {e}")
            return False

    def run(self):
        print("=" * 52)
        print("      REALISTIC ZTNA SESSION LIFECYCLE")
        print("=" * 52)
        print()

        # ── Step 1: Authenticate ONCE ─────────────────────────
        print("STEP 1: Authenticate and create a session ONCE")
        self.authenticate()
        if not self.session_id:
            print("[ABORT] No session. Exiting.")
            return

        # ── Step 2: Normal traffic ─────────────────────────────
        print("\nSTEP 2: Normal requests — reusing same session")
        for _ in range(5):
            if not self.simulate_access():
                break
            time.sleep(1)

        # ── Step 3: Slightly faster traffic ───────────────────
        print("\nSTEP 3: Faster requests — monitor behaviour")
        for _ in range(8):
            if not self.simulate_access():
                break
            time.sleep(0.3)

        # ── Step 4: Stolen token (IP change) ──────────────────
        print("\nSTEP 4: Attacker steals token — IP mismatch")
        self.simulate_access(steal_token=True)

        # ── Step 5: Legitimate user retries ───────────────────
        print("\nSTEP 5: Legitimate user retries with same session")
        self.simulate_access(steal_token=False)

        print("\n" + "=" * 52)
        print("Simulation complete.")
        print("=" * 52)


if __name__ == "__main__":
    sim = ZTNASimulator()
    sim.run()