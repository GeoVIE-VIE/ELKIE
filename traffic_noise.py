#!/usr/bin/env python3
"""
Traffic Noise Generator — Privacy Defense Daemon

Generates realistic-looking web traffic to poison data broker profiles.
Makes randomized HTTP/HTTPS requests to thousands of legitimate sites
at a natural cadence, making real browsing activity indistinguishable
from generated noise.

Features:
- Weighted category selection (mimics real browsing patterns)
- Randomized timing (no detectable pattern)
- Rotates user agents
- Follows redirects like a real browser
- DNS queries to diverse domains (poisons ISP DNS logs)
- Runs 24/7 as a systemd service
"""

import argparse
import json
import logging
import os
import random
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    log_file: str = "/home/legs/traffic_noise.log"
    min_interval: int = 5       # minimum seconds between requests
    max_interval: int = 45      # maximum seconds between requests
    burst_chance: float = 0.15  # chance of a rapid burst (simulates browsing session)
    burst_size: int = 8         # max requests in a burst
    quiet_hours: bool = True    # reduce traffic 1am-6am (looks more natural)

# ---------------------------------------------------------------------------
# URL pools by category — weighted to look like real browsing
# ---------------------------------------------------------------------------

CATEGORIES = {
    "news": {
        "weight": 20,
        "urls": [
            "https://www.cnn.com", "https://www.bbc.com", "https://www.reuters.com",
            "https://www.nytimes.com", "https://www.washingtonpost.com",
            "https://www.theguardian.com", "https://news.ycombinator.com",
            "https://www.npr.org", "https://www.aljazeera.com",
            "https://www.usatoday.com", "https://abcnews.go.com",
            "https://www.foxnews.com", "https://www.cbsnews.com",
            "https://www.nbcnews.com", "https://www.politico.com",
            "https://www.thehill.com", "https://apnews.com",
            "https://www.axios.com", "https://www.vox.com",
        ],
    },
    "shopping": {
        "weight": 18,
        "urls": [
            "https://www.amazon.com", "https://www.walmart.com",
            "https://www.target.com", "https://www.bestbuy.com",
            "https://www.homedepot.com", "https://www.lowes.com",
            "https://www.costco.com", "https://www.macys.com",
            "https://www.nordstrom.com", "https://www.zappos.com",
            "https://www.etsy.com", "https://www.ebay.com",
            "https://www.wayfair.com", "https://www.ikea.com",
            "https://www.kohls.com", "https://www.newegg.com",
            "https://www.bhphotovideo.com", "https://www.rei.com",
        ],
    },
    "tech": {
        "weight": 15,
        "urls": [
            "https://www.github.com", "https://stackoverflow.com",
            "https://www.reddit.com/r/programming", "https://www.reddit.com/r/technology",
            "https://arstechnica.com", "https://www.theverge.com",
            "https://techcrunch.com", "https://www.wired.com",
            "https://slashdot.org", "https://www.tomshardware.com",
            "https://www.anandtech.com", "https://hackernoon.com",
            "https://dev.to", "https://medium.com",
            "https://www.digitalocean.com/community",
        ],
    },
    "social": {
        "weight": 12,
        "urls": [
            "https://www.reddit.com", "https://www.reddit.com/r/popular",
            "https://www.reddit.com/r/news", "https://www.reddit.com/r/funny",
            "https://www.reddit.com/r/science", "https://www.reddit.com/r/gaming",
            "https://www.reddit.com/r/movies", "https://www.reddit.com/r/todayilearned",
            "https://www.twitter.com", "https://www.instagram.com",
            "https://www.facebook.com", "https://www.linkedin.com",
            "https://www.pinterest.com", "https://www.tumblr.com",
        ],
    },
    "finance": {
        "weight": 10,
        "urls": [
            "https://www.bankrate.com", "https://www.nerdwallet.com",
            "https://finance.yahoo.com", "https://www.marketwatch.com",
            "https://www.cnbc.com", "https://www.bloomberg.com",
            "https://www.investopedia.com", "https://www.fool.com",
            "https://www.fidelity.com", "https://www.schwab.com",
            "https://www.mint.com", "https://www.creditkarma.com",
        ],
    },
    "entertainment": {
        "weight": 10,
        "urls": [
            "https://www.youtube.com", "https://www.netflix.com",
            "https://www.twitch.tv", "https://www.spotify.com",
            "https://www.imdb.com", "https://www.rottentomatoes.com",
            "https://www.hulu.com", "https://www.disneyplus.com",
            "https://www.crunchyroll.com", "https://www.audible.com",
            "https://store.steampowered.com", "https://www.epicgames.com",
        ],
    },
    "health": {
        "weight": 5,
        "urls": [
            "https://www.webmd.com", "https://www.mayoclinic.org",
            "https://www.healthline.com", "https://www.nih.gov",
            "https://www.cdc.gov", "https://www.medlineplus.gov",
            "https://www.medicalnewstoday.com", "https://www.everydayhealth.com",
        ],
    },
    "education": {
        "weight": 5,
        "urls": [
            "https://www.khanacademy.org", "https://www.coursera.org",
            "https://www.udemy.com", "https://www.edx.org",
            "https://www.wikipedia.org", "https://scholar.google.com",
            "https://www.britannica.com", "https://www.mit.edu",
        ],
    },
    "travel": {
        "weight": 3,
        "urls": [
            "https://www.booking.com", "https://www.expedia.com",
            "https://www.airbnb.com", "https://www.tripadvisor.com",
            "https://www.kayak.com", "https://www.hotels.com",
            "https://www.southwest.com", "https://www.united.com",
        ],
    },
    "adult": {
        "weight": 8,
        "urls": [
            "https://www.pornhub.com", "https://www.xvideos.com",
            "https://www.xnxx.com", "https://www.redtube.com",
            "https://www.youporn.com", "https://www.xhamster.com",
            "https://www.chaturbate.com", "https://www.onlyfans.com",
            "https://www.brazzers.com", "https://www.bangbros.com",
            "https://www.adam4adam.com", "https://www.grindr.com",
            "https://www.scruff.com", "https://www.xtube.com",
            "https://www.gaymaletube.com", "https://www.planetromeo.com",
        ],
    },
    "adult_search": {
        "weight": 5,
        "urls": [
            "https://www.google.com/search?q=best+dating+apps+2026",
            "https://www.google.com/search?q=lgbtq+dating+near+me",
            "https://www.google.com/search?q=gay+bars+near+me",
            "https://www.google.com/search?q=pride+events+2026",
            "https://www.google.com/search?q=transgender+resources",
            "https://www.google.com/search?q=queer+community+groups",
            "https://www.google.com/search?q=bisexual+dating+tips",
            "https://www.google.com/search?q=nonbinary+clothing+brands",
            "https://www.google.com/search?q=lesbian+travel+destinations",
            "https://www.google.com/search?q=drag+shows+near+me",
            "https://www.google.com/search?q=polyamory+relationship+advice",
            "https://www.google.com/search?q=fetlife+alternatives",
            "https://www.google.com/search?q=adult+toys+review",
            "https://www.google.com/search?q=couples+therapy+near+me",
            "https://www.bing.com/search?q=best+porn+sites+2026",
            "https://www.bing.com/search?q=onlyfans+creators",
            "https://duckduckgo.com/?q=anonymous+hookup+apps",
            "https://duckduckgo.com/?q=sex+positive+communities",
        ],
    },
    "dating": {
        "weight": 4,
        "urls": [
            "https://www.tinder.com", "https://www.bumble.com",
            "https://www.hinge.com", "https://www.match.com",
            "https://www.okcupid.com", "https://www.plentyoffish.com",
            "https://www.eharmony.com", "https://www.zoosk.com",
            "https://www.grindr.com", "https://www.her.app",
            "https://www.feeld.co", "https://www.taimi.com",
        ],
    },
    "search": {
        "weight": 12,
        "urls": [
            "https://www.google.com/search?q=best+wireless+headphones",
            "https://www.google.com/search?q=python+tutorial",
            "https://www.google.com/search?q=weather+today",
            "https://www.google.com/search?q=recipe+chicken+parmesan",
            "https://www.google.com/search?q=how+to+fix+leaky+faucet",
            "https://www.google.com/search?q=best+laptop+2026",
            "https://www.google.com/search?q=local+restaurants+near+me",
            "https://www.google.com/search?q=mortgage+rates",
            "https://www.google.com/search?q=oil+change+near+me",
            "https://www.google.com/search?q=diy+home+improvement",
            "https://www.bing.com/search?q=new+movies+2026",
            "https://www.bing.com/search?q=cybersecurity+jobs",
            "https://duckduckgo.com/?q=privacy+tools",
            "https://duckduckgo.com/?q=vpn+comparison",
        ],
    },
}

# Diverse user agents to prevent fingerprinting the noise generator itself
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
]

# ---------------------------------------------------------------------------
# Noise generator
# ---------------------------------------------------------------------------

class TrafficNoise:

    def __init__(self, config: Config):
        self.cfg = config
        self.running = True
        self.logger = self._setup_logging()
        self.session = requests.Session()
        self.total_requests = 0
        self.categories_hit = {}
        self._es_url = "http://localhost:9200"
        self._es_index = "traffic-noise"
        self._ensure_es_index()

        # Build weighted category list
        self._weighted_categories = []
        for cat, data in CATEGORIES.items():
            self._weighted_categories.extend([cat] * data["weight"])

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("traffic_noise")
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

        fh = RotatingFileHandler(self.cfg.log_file, maxBytes=5_000_000, backupCount=3)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

        return logger

    def _ensure_es_index(self):
        """Create traffic-noise index with mappings."""
        try:
            resp = requests.get(f"{self._es_url}/{self._es_index}", timeout=5)
            if resp.status_code == 200:
                return
            requests.put(f"{self._es_url}/{self._es_index}", json={
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "category": {"type": "keyword"},
                        "url": {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "status_code": {"type": "integer"},
                        "success": {"type": "boolean"},
                        "user_agent": {"type": "keyword"},
                        "is_burst": {"type": "boolean"},
                    }
                },
                "settings": {"number_of_shards": 1, "number_of_replicas": 0}
            }, timeout=5)
            self.logger.info("Created ES index '%s'", self._es_index)
        except Exception:
            pass

    def _index_request(self, url: str, category: str, status_code: int, success: bool, user_agent: str, is_burst: bool):
        """Index a noise request to ES for Grafana visibility."""
        import re as _re
        domain_match = _re.search(r"https?://([^/]+)", url)
        domain = domain_match.group(1) if domain_match else "unknown"

        # Extract search query from URL if present
        import urllib.parse as _urlparse
        search_query = ""
        try:
            parsed = _urlparse.urlparse(url)
            params = _urlparse.parse_qs(parsed.query)
            search_query = params.get("q", params.get("query", [""]))[0].replace("+", " ")
        except Exception:
            pass

        try:
            doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "category": category,
                "url": url[:200],
                "domain": domain,
                "status_code": status_code,
                "success": success,
                "user_agent": user_agent[:50],
                "is_burst": is_burst,
                "source": "traffic-noise",
                "source_ip": "192.168.50.3",
            }
            if search_query:
                doc["search_query"] = search_query
            requests.post(f"{self._es_url}/{self._es_index}/_doc", json=doc, timeout=3)
        except Exception:
            pass

    # -- Search query generation (template-based for infinite variety) ----

    _QUERY_TEMPLATES = {
        "search": {
            "templates": [
                "best {product} {year}", "how to {fix_action} {household_item}",
                "{recipe_adj} {food} recipe", "{food} recipe for {occasion}",
                "weather in {city} this week", "best {product} under {price}",
                "{service} near me", "diy {home_project}", "how to {life_skill}",
                "best {product} for {use_case}", "{city} things to do this weekend",
                "how much does {service} cost", "{brand} vs {brand} review",
                "is {product} worth it {year}", "cheap {product} deals",
                "how to clean {household_item}", "best {food} restaurants in {city}",
                "{car_brand} {car_type} {year} review", "used {car_brand} for sale near me",
                "how to save money on {expense}", "{sport} scores today",
                "{streaming} best shows {year}", "when does {show} come out",
                "best books {genre} {year}", "how to lose weight {method}",
                "{exercise} workout for beginners", "best {supplement} for {health_goal}",
                "{home_project} cost estimate", "how to {cooking_method} {food}",
                "best {pet} breeds for {living_situation}", "{pet} {pet_issue} remedies",
                "how to get rid of {pest}", "{holiday} gift ideas {year}",
                "best {clothing} for {season}", "how to style {clothing}",
            ],
            "vars": {
                "product": ["wireless headphones", "laptop", "monitor", "keyboard", "mouse",
                    "air fryer", "vacuum cleaner", "mattress", "office chair", "standing desk",
                    "smart watch", "tablet", "router", "dash cam", "security camera",
                    "blender", "instant pot", "coffee maker", "air purifier", "dehumidifier",
                    "electric toothbrush", "noise canceling earbuds", "portable charger",
                    "gaming headset", "webcam", "microphone", "ring light", "power strip",
                    "lawn mower", "pressure washer", "drill", "tool set", "generator"],
                "year": ["2025", "2026"],
                "fix_action": ["fix", "repair", "replace", "install", "unclog", "patch", "adjust", "rewire"],
                "household_item": ["leaky faucet", "running toilet", "garbage disposal", "dishwasher",
                    "dryer", "washing machine", "water heater", "thermostat", "smoke detector",
                    "ceiling fan", "light switch", "door knob", "window screen", "gutter",
                    "drywall hole", "squeaky door", "garage door opener", "sprinkler system"],
                "recipe_adj": ["easy", "quick", "healthy", "keto", "vegan", "gluten free",
                    "slow cooker", "instant pot", "air fryer", "one pot", "30 minute",
                    "budget", "meal prep", "high protein", "low carb", "mediterranean"],
                "food": ["chicken", "salmon", "pasta", "tacos", "steak", "shrimp", "tofu",
                    "rice bowl", "soup", "chili", "curry", "stir fry", "pizza dough",
                    "banana bread", "pancakes", "smoothie", "meatloaf", "pulled pork",
                    "mac and cheese", "fried rice", "ramen", "burrito bowl", "lasagna"],
                "occasion": ["dinner tonight", "meal prep", "date night", "family dinner",
                    "super bowl party", "birthday party", "potluck", "camping", "kids"],
                "city": ["Portland", "Austin", "Denver", "Seattle", "Nashville", "San Diego",
                    "Miami", "Chicago", "Boston", "Atlanta", "Phoenix", "Las Vegas",
                    "New York", "Los Angeles", "Houston", "Dallas", "Philadelphia"],
                "service": ["oil change", "dentist", "urgent care", "tire shop", "barber",
                    "mechanic", "plumber", "electrician", "dog groomer", "dry cleaner",
                    "gym", "yoga studio", "nail salon", "tattoo shop", "chiropractor"],
                "home_project": ["bathroom remodel", "kitchen backsplash", "deck building",
                    "fence installation", "painting interior walls", "installing shelves",
                    "garden bed raised", "patio pavers", "closet organization",
                    "basement finishing", "attic insulation", "crown molding"],
                "life_skill": ["negotiate salary", "build credit", "file taxes",
                    "change a tire", "jump start a car", "parallel park",
                    "tie a tie", "iron a shirt", "sew a button",
                    "write a resume", "ace a job interview", "meal prep for the week"],
                "use_case": ["small apartment", "large family", "beginners", "seniors",
                    "college students", "remote work", "travel", "outdoors", "gaming"],
                "brand": ["Samsung", "Apple", "Sony", "LG", "Nike", "Adidas",
                    "Toyota", "Honda", "Tesla", "Dyson", "Ninja", "KitchenAid"],
                "price": ["$50", "$100", "$200", "$500", "$1000"],
                "car_brand": ["Toyota", "Honda", "Ford", "Chevy", "Tesla", "Hyundai", "Kia", "BMW", "Subaru"],
                "car_type": ["SUV", "sedan", "truck", "hybrid", "electric"],
                "expense": ["groceries", "gas", "insurance", "utilities", "rent", "internet"],
                "sport": ["NFL", "NBA", "MLB", "UFC", "soccer", "college basketball"],
                "streaming": ["Netflix", "Hulu", "Disney Plus", "HBO Max", "Prime Video", "Peacock"],
                "show": ["Stranger Things season 5", "The Last of Us season 3", "House of the Dragon",
                    "Yellowstone", "Wednesday season 2", "Squid Game season 3"],
                "genre": ["thriller", "romance", "sci fi", "fantasy", "self help", "biography"],
                "method": ["intermittent fasting", "walking", "without exercise", "naturally", "keto"],
                "exercise": ["ab", "arm", "leg", "full body", "HIIT", "yoga", "pilates", "cardio"],
                "supplement": ["protein powder", "creatine", "multivitamin", "fish oil", "pre workout", "collagen"],
                "health_goal": ["muscle gain", "energy", "sleep", "joint pain", "weight loss", "recovery"],
                "cooking_method": ["grill", "smoke", "sous vide", "deep fry", "bake", "roast", "sear"],
                "pet": ["dog", "cat", "fish", "hamster", "rabbit"],
                "pet_issue": ["anxiety", "shedding", "bad breath", "fleas", "itching", "not eating"],
                "living_situation": ["apartments", "families with kids", "first time owners", "active people"],
                "pest": ["ants", "mice", "roaches", "fruit flies", "mosquitoes", "wasps", "termites"],
                "holiday": ["Christmas", "birthday", "anniversary", "valentines day", "mothers day", "fathers day"],
                "clothing": ["jeans", "sneakers", "dress shirt", "winter jacket", "swim trunks", "boots"],
                "season": ["summer", "winter", "spring", "fall"],
            },
        },
        "adult_search": {
            "templates": [
                "best {adj} porn", "{category} videos", "{category} {adj}",
                "pornhub {category}", "xvideos {category} {adj}",
                "{ethnicity} {category}", "{body_type} {category}",
                "best {platform} creators {year}", "top {platform} accounts",
                "{position} tutorial", "how to {sex_skill}",
                "best {toy} for {gender}", "{toy} review {year}",
                "{kink} for beginners", "how to try {kink} safely",
                "{relationship} dating advice", "{relationship} relationship tips",
                "best {dating_app} tips", "{dating_app} vs {dating_app}",
                "how to {dating_action}", "{gender} {dating_action} tips",
                "{adj} {gender} onlyfans", "free {category} videos",
                "{body_part} {adj}", "big {body_part} {category}",
                "amateur {category} {ethnicity}", "homemade {category}",
                "{orientation} {category} videos", "{orientation} porn best",
                "{orientation} dating apps", "{orientation} bars near me",
                "trans {category}", "transgender {dating_action}",
                "ftm dating advice", "mtf passing tips",
                "nonbinary {category}", "genderfluid fashion",
                "drag queen {city} shows", "pride events {city} {year}",
                "queer friendly {service} near me", "lgbtq therapist near me",
                "coming out as {orientation}", "how to support {orientation} partner",
                "{orientation} romance books", "{orientation} movies {year}",
            ],
            "vars": {
                "adj": ["hot", "best", "top rated", "new", "trending", "popular", "amateur",
                    "professional", "HD", "homemade", "real", "passionate", "rough",
                    "sensual", "romantic", "intense", "wild", "gentle", "hardcore", "soft"],
                "category": ["milf", "teen 18+", "mature", "couple", "threesome", "solo",
                    "lesbian", "gay", "bisexual", "trans", "interracial", "latina",
                    "asian", "ebony", "blonde", "brunette", "redhead", "BBW",
                    "petite", "curvy", "muscular", "tattooed", "pierced",
                    "massage", "stepmom", "stepsister", "teacher", "nurse",
                    "cosplay", "outdoor", "shower", "pool", "public",
                    "anal", "oral", "creampie", "squirt", "bondage",
                    "roleplay", "POV", "gangbang", "orgy", "swingers"],
                "ethnicity": ["latina", "ebony", "asian", "indian", "middle eastern",
                    "european", "japanese", "korean", "filipina", "brazilian",
                    "colombian", "mexican", "african", "caribbean", "mixed race",
                    "white", "black", "arab", "persian", "thai"],
                "body_type": ["petite", "curvy", "thick", "slim", "athletic", "BBW",
                    "fit", "muscular", "tall", "short", "voluptuous", "skinny",
                    "plus size", "hourglass", "pear shaped", "busty", "flat chested"],
                "body_part": ["boobs", "ass", "dick", "tits", "butt", "cock",
                    "breasts", "thighs", "abs", "feet", "legs"],
                "position": ["missionary", "doggy style", "cowgirl", "reverse cowgirl",
                    "69", "spooning", "standing", "prone bone", "lotus",
                    "wheelbarrow", "pretzel", "butterfly"],
                "sex_skill": ["last longer in bed", "give better head",
                    "find the g spot", "have multiple orgasms",
                    "be better at foreplay", "talk dirty", "use handcuffs safely",
                    "introduce toys in bedroom", "have anal sex safely",
                    "improve stamina", "give a prostate massage",
                    "eat pussy", "give a blowjob", "edge properly"],
                "toy": ["vibrator", "dildo", "butt plug", "cock ring", "fleshlight",
                    "strap on", "prostate massager", "wand massager", "nipple clamps",
                    "bondage kit", "sex swing", "remote vibrator", "suction toy"],
                "gender": ["women", "men", "couples", "him", "her", "nonbinary people"],
                "kink": ["BDSM", "bondage", "role play", "foot fetish", "domination",
                    "submission", "edging", "pegging", "cuckolding", "voyeurism",
                    "exhibitionism", "sensory deprivation", "wax play", "spanking",
                    "choking", "double penetration", "group sex", "swinging"],
                "relationship": ["open relationship", "polyamorous", "monogamous",
                    "long distance", "friends with benefits", "casual",
                    "dom sub", "sugar daddy", "cougar", "age gap"],
                "dating_app": ["Tinder", "Bumble", "Hinge", "Grindr", "Her",
                    "Feeld", "OkCupid", "Scruff", "Taimi", "3Fun"],
                "dating_action": ["flirt", "sext", "send nudes safely",
                    "have a one night stand", "find a hookup",
                    "ask someone out", "recover from rejection",
                    "write a bio", "take good dating photos"],
                "platform": ["OnlyFans", "Fansly", "Pornhub", "Chaturbate", "ManyVids"],
                "orientation": ["gay", "lesbian", "bisexual", "pansexual", "queer",
                    "asexual", "demisexual", "heteroflexible", "bicurious", "straight"],
                "city": ["NYC", "LA", "San Francisco", "Miami", "Chicago",
                    "Atlanta", "Portland", "Austin", "New Orleans", "Seattle"],
                "service": ["doctor", "therapist", "gym", "bar", "church",
                    "community center", "bookstore", "cafe", "salon"],
                "year": ["2025", "2026"],
            },
        },
    }

    def _generate_search_query(self, category: str) -> str:
        """Generate a realistic search query from templates."""
        # Map category to template set
        if category == "adult_search":
            tset = self._QUERY_TEMPLATES["adult_search"]
        else:
            tset = self._QUERY_TEMPLATES["search"]

        template = random.choice(tset["templates"])
        variables = tset["vars"]

        # Replace all {placeholders} with random values
        import re as _re
        def replace_var(match):
            var_name = match.group(1)
            if var_name in variables:
                return random.choice(variables[var_name])
            return match.group(0)

        query = _re.sub(r'\{(\w+)\}', replace_var, template)
        return query

    def _pick_url(self) -> tuple[str, str]:
        """Pick a random URL from a weighted category."""
        category = random.choice(self._weighted_categories)
        url = random.choice(CATEGORIES[category]["urls"])

        # Sometimes replace with a dynamically generated realistic search query
        if "search" in category and random.random() < 0.3:
            query = self._generate_search_query(category)
            engine = random.choice(["https://www.google.com/search", "https://www.bing.com/search", "https://duckduckgo.com/"])
            url = f"{engine}?q={query.replace(' ', '+')}"

        return url, category

    def _make_request(self, url: str, category: str = "", is_burst: bool = False) -> bool:
        """Make a single HTTP request that looks like real browsing."""
        ua = random.choice(USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

        # Sometimes add a referer (simulates clicking links)
        if random.random() < 0.4:
            referers = [
                "https://www.google.com/", "https://www.bing.com/",
                "https://duckduckgo.com/", "https://www.reddit.com/",
                "https://news.ycombinator.com/", "https://t.co/",
            ]
            headers["Referer"] = random.choice(referers)

        try:
            resp = self.session.get(
                url, headers=headers, timeout=10,
                allow_redirects=True,
                stream=True,  # Don't download full body
            )
            # Read just enough to trigger the connection
            resp.raw.read(1024)
            status = resp.status_code
            resp.close()
            self._index_request(url, category, status, True, ua, is_burst)
            return True
        except Exception:
            self._index_request(url, category, 0, False, ua, is_burst)
            return False

    def _get_sleep_time(self) -> float:
        """Get next sleep interval with natural variance."""
        now = datetime.now()
        hour = now.hour

        # Quiet hours: 1am-6am — less traffic
        if self.cfg.quiet_hours and 1 <= hour <= 5:
            return random.uniform(30, 120)

        # Peak hours: 7am-11pm — more traffic
        base_min = self.cfg.min_interval
        base_max = self.cfg.max_interval

        # Add some randomness
        return random.uniform(base_min, base_max)

    def run(self):
        self.logger.info("Traffic Noise Generator starting — %d categories, %d URLs",
                         len(CATEGORIES), sum(len(c["urls"]) for c in CATEGORIES.values()))

        while self.running:
            # Decide: single request or burst
            if random.random() < self.cfg.burst_chance:
                # Burst: simulate a browsing session
                burst_count = random.randint(3, self.cfg.burst_size)
                # Pick a primary category for the session
                session_cat = random.choice(self._weighted_categories)
                self.logger.info("Burst session: %d requests (%s)", burst_count, session_cat)

                for i in range(burst_count):
                    if not self.running:
                        break
                    # 70% from session category, 30% random
                    if random.random() < 0.7:
                        url = random.choice(CATEGORIES[session_cat]["urls"])
                        cat = session_cat
                    else:
                        url, cat = self._pick_url()

                    ok = self._make_request(url, cat, is_burst=True)
                    self.total_requests += 1
                    self.categories_hit[cat] = self.categories_hit.get(cat, 0) + 1

                    # Short pause between burst requests (1-5s)
                    time.sleep(random.uniform(1, 5))

            else:
                # Single request
                url, cat = self._pick_url()
                ok = self._make_request(url, cat, is_burst=False)
                self.total_requests += 1
                self.categories_hit[cat] = self.categories_hit.get(cat, 0) + 1

            # Log stats periodically
            if self.total_requests % 100 == 0:
                top_cats = sorted(self.categories_hit.items(), key=lambda x: -x[1])[:5]
                cats_str = ", ".join(f"{c}={n}" for c, n in top_cats)
                self.logger.info("Stats: %d total requests | %s", self.total_requests, cats_str)

            sleep_time = self._get_sleep_time()
            time.sleep(sleep_time)

        self.logger.info("Traffic Noise Generator stopped — %d total requests", self.total_requests)

    def stop(self):
        self.running = False

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Traffic Noise Generator — Privacy Defense")
    parser.add_argument("--min-interval", type=int, default=5)
    parser.add_argument("--max-interval", type=int, default=45)
    parser.add_argument("--log-file", default="/home/legs/traffic_noise.log")
    parser.add_argument("--no-quiet-hours", action="store_true", help="Don't reduce traffic at night")
    args = parser.parse_args()

    config = Config(
        log_file=args.log_file,
        min_interval=args.min_interval,
        max_interval=args.max_interval,
        quiet_hours=not args.no_quiet_hours,
    )

    noise = TrafficNoise(config)

    def handle_signal(signum, frame):
        noise.logger.info("Received signal %d — stopping", signum)
        noise.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    noise.run()

if __name__ == "__main__":
    main()
