
import os
import logging
from datetime import datetime, timezone
from functools import wraps

import certifi
from flask import Flask, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_KEY = os.getenv("API_KEY")
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")

client = None
db = None
startup_error = None

# Connect to MongoDB
try:
    if not MONGODB_URI:
        raise ValueError("MONGODB_URI is missing")

    client = MongoClient(
        MONGODB_URI,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=5000,
    )
    client.admin.command("ping")
    db = client[DATABASE_NAME]
    startup_error = None
    logger.info("MongoDB connected successfully")

except Exception:
    startup_error = "Database unavailable"
    logger.exception("MongoDB connection failed")


def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not API_KEY:
            return jsonify({
                "success": False,
                "error": "API key is not configured"
            }), 503

        supplied_key = request.headers.get("x-api-key", "")

        # Constant-time comparison
        import hmac
        if not hmac.compare_digest(supplied_key, API_KEY):
            return jsonify({
                "success": False,
                "error": "Unauthorized"
            }), 401

        return func(*args, **kwargs)

    return wrapper


@app.get("/")
def index():
    return jsonify({
        "name": "Telegram Bot API",
        "status": "running",
        "health": "/api/v1/health"
    })


@app.get("/api/v1/health")
def health():
    if db is None:
        return jsonify({
            "status": "error",
            "error": startup_error or "Database unavailable"
        }), 503

    try:
        client.admin.command("ping")
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0"
        })
    except Exception:
        logger.exception("Health check failed")
        return jsonify({
            "status": "error",
            "error": "Database unavailable"
        }), 503


@app.get("/api/v1/stats")
@require_api_key
def stats():
    if db is None:
        return jsonify({
            "success": False,
            "error": "Database unavailable"
        }), 503

    try:
        total_users = db.users.count_documents({})
        approved_users = db.users.count_documents({
            "approved": True,
            "is_banned": {"$ne": True}
        })
        total_jobs = db.attacks.count_documents({})

        return jsonify({
            "success": True,
            "status": "ok",
            "totalUsers": total_users,
            "approvedUsers": approved_users,
            "totalRecords": total_jobs
        })
    except Exception:
        logger.exception("Statistics request failed")
        return jsonify({
            "success": False,
            "error": "Unable to retrieve statistics"
        }), 500


@app.get("/api/v1/active")
@require_api_key
def active():
    # Monitoring only; does not execute network attacks.
    return jsonify({
        "success": True,
        "activeAttacks": [],
        "count": 0,
        "maxConcurrent": 0,
        "remainingSlots": 0,
        "message": "Execution service is disabled"
    })


@app.post("/api/v1/attack")
@require_api_key
def disabled_execution():
    # Deliberately disabled.
    return jsonify({
        "success": False,
        "error": "Execution endpoint disabled",
        "message": (
            "Use an authorized load-testing tool against "
            "systems you own or have permission to test."
        )
    }), 403


@app.errorhandler(404)
def not_found(_error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({
        "success": False,
        "error": "Method not allowed"
    }), 405


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
