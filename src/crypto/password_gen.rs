use rand::Rng;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

const WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "acid", "acoustic", "acquire", "across", "action",
    "actor", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic",
    "afford", "afraid", "again", "agent", "agree", "ahead", "aim", "air",
    "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "almost",
    "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing",
    "among", "amount", "amused", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "apart", "apology", "appear", "apple", "approve", "arena", "argue",
    "armor", "army", "arrest", "arrive", "arrow", "artist", "asthma", "atom",
    "attack", "attend", "attract", "auction", "audit", "august", "aunt", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "awesome", "awful", "awkward",
    "banana", "banner", "bargain", "barrel", "basket", "battle", "beach", "bean",
    "beauty", "become", "before", "begin", "behave", "believe", "bench", "benefit",
    "best", "betray", "beyond", "bicycle", "bitter", "blanket", "bless", "blind",
    "blood", "blossom", "board", "bonus", "bottom", "bounce", "brave", "bread",
    "breeze", "brick", "bridge", "bright", "bring", "broken", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "burden", "burger",
    "butter", "cabin", "cable", "cactus", "camera", "camp", "canal", "cancel",
    "canvas", "canyon", "capable", "captain", "carbon", "cargo", "carpet", "carry",
    "castle", "catalog", "catch", "cattle", "caught", "cause", "caution", "cave",
    "celery", "cement", "census", "century", "cereal", "certain", "chair", "change",
    "chapter", "charge", "cherry", "chicken", "chief", "child", "chimney", "choice",
    "chunk", "circle", "citizen", "claim", "clap", "clarify", "claw", "clean",
    "clever", "cliff", "climb", "clinic", "clip", "clock", "close", "cloth",
    "cloud", "cluster", "coach", "coconut", "coffee", "collect", "color", "column",
    "combine", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
    "connect", "consider", "control", "convince", "copper", "coral", "corner", "correct",
    "cotton", "couch", "country", "couple", "course", "cousin", "cover", "craft",
    "crane", "crash", "crater", "cream", "credit", "creek", "crew", "cricket",
    "crime", "crisp", "cruel", "cruise", "crumble", "crush", "crystal", "cube",
    "culture", "curtain", "curve", "cushion", "custom", "cycle", "damage", "dance",
    "danger", "daring", "daughter", "dawn", "debate", "debris", "decade", "december",
    "decide", "defense", "define", "degree", "delay", "demand", "denial", "dentist",
    "depart", "depend", "deposit", "depth", "deputy", "derive", "desert", "design",
    "detail", "detect", "develop", "device", "devote", "diamond", "diary", "diesel",
    "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "disease",
    "dismiss", "display", "distance", "divert", "document", "dolphin", "domain", "donate",
    "donkey", "donor", "double", "dove", "draft", "dragon", "drama", "dress",
    "drift", "drink", "drip", "drive", "drum", "dry", "duck", "dumb",
    "dune", "during", "dust", "dutch", "dwarf", "dynamic", "eager", "eagle",
    "earth", "easily", "ecology", "economy", "edge", "effort", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite",
    "embrace", "emerge", "emotion", "employ", "empower", "enable", "endorse", "enemy",
    "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enough", "enrich",
    "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip",
    "erode", "erosion", "error", "escape", "essay", "essence", "estate", "eternal",
    "evidence", "evil", "evolve", "exact", "example", "excess", "exchange", "excite",
    "exclude", "excuse", "execute", "exhaust", "exhibit", "exile", "expand", "expect",
    "expire", "explain", "expose", "express", "extend", "extra", "eyebrow", "fabric",
    "faculty", "faint", "faith", "fall", "famous", "fancy", "fantasy", "fashion",
    "father", "fault", "favorite", "feature", "february", "federal", "fence", "festival",
    "fetch", "fever", "fiction", "field", "figure", "filter", "final", "finger",
    "finish", "fire", "firm", "fiscal", "fitness", "flag", "flame", "flash",
    "flavor", "flight", "flip", "float", "flock", "floor", "flower", "fluid",
    "focus", "follow", "food", "force", "forest", "forget", "fork", "fortune",
    "fossil", "foster", "found", "fragile", "frame", "frequent", "fresh", "friend",
    "fringe", "frog", "frozen", "fruit", "funny", "furnace", "fury", "future",
    "gadget", "galaxy", "gallery", "game", "garage", "garbage", "garden", "garlic",
    "gather", "gauge", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "glance", "glare",
    "glass", "globe", "gloom", "glory", "glove", "glow", "glue", "goat",
    "goddess", "gold", "gospel", "gossip", "govern", "grace", "grain", "gravity",
    "great", "green", "grid", "grief", "grocery", "group", "grow", "grunt",
    "guard", "guess", "guide", "guilt", "guitar", "habitat", "hammer", "hamster",
    "harbor", "harsh", "harvest", "hawk", "hazard", "helmet", "hero", "highway",
    "history", "hobby", "hollow", "honey", "hood", "hope", "horn", "horror",
    "hospital", "host", "hover", "humble", "humor", "hundred", "hungry", "hurdle",
    "hurry", "husband", "hybrid", "icon", "idea", "identify", "ignore", "image",
    "imitate", "immense", "immune", "impact", "import", "impose", "improve", "impulse",
    "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant",
    "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inner",
    "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install",
    "intact", "interest", "into", "invest", "invite", "iron", "island", "isolate",
    "ivory", "jacket", "jaguar", "jealous", "jelly", "jewel", "journey", "judge",
    "jungle", "junior", "justice", "kangaroo", "keen", "kernel", "kidney", "kingdom",
    "kitchen", "kitten", "kiwi", "knife", "knock", "label", "ladder", "lake",
    "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry",
    "lawn", "lawsuit", "layer", "leader", "leaf", "learn", "leave", "lecture",
    "legal", "legend", "leisure", "lemon", "length", "leopard", "lesson", "letter",
    "level", "liberty", "library", "license", "lift", "limb", "limit", "link",
    "lion", "liquid", "little", "lizard", "loan", "lobster", "logic", "lonely",
    "loop", "lottery", "luggage", "lunar", "luxury", "machine", "magnet", "mango",
    "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market",
    "mask", "master", "match", "material", "matrix", "maximum", "meadow", "measure",
    "media", "melody", "member", "memory", "mention", "mentor", "mercy", "merge",
    "message", "metal", "method", "middle", "million", "mimic", "minimum", "miracle",
    "mirror", "misery", "mixture", "mobile", "model", "modify", "moment", "monitor",
    "monkey", "monster", "month", "moral", "morning", "mosquito", "mother", "motion",
    "mountain", "mouse", "movie", "multiply", "muscle", "museum", "mushroom", "music",
    "mystery", "myth", "napkin", "narrow", "nation", "nature", "navigate", "negative",
    "neglect", "neither", "nephew", "nerve", "network", "neutral", "noble", "noise",
    "nominee", "normal", "notable", "nothing", "notice", "novel", "nuclear", "number",
    "nurse", "object", "observe", "obtain", "obvious", "ocean", "october", "odor",
    "offer", "office", "often", "olive", "olympic", "omit", "online", "opera",
    "opinion", "oppose", "option", "orange", "orbit", "orchard", "ordinary", "organ",
    "orient", "original", "orphan", "ostrich", "outdoor", "outer", "output", "outside",
    "oval", "oven", "owner", "oxygen", "oyster", "ozone", "paddle", "palace",
    "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park",
    "parrot", "party", "patch", "path", "patient", "patrol", "pattern", "pause",
    "peanut", "pelican", "penalty", "pencil", "people", "pepper", "perfect", "permit",
    "person", "phrase", "piano", "picnic", "picture", "piece", "pilot", "pioneer",
    "pistol", "pizza", "planet", "plastic", "plate", "pluck", "plug", "plunge",
    "poem", "point", "polar", "ponder", "pony", "pool", "popular", "position",
    "potato", "pottery", "poverty", "powder", "power", "practice", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "primary", "priority", "prison", "private",
    "problem", "process", "produce", "profit", "program", "project", "promote", "proof",
    "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pulse",
    "pumpkin", "punch", "pupil", "puppy", "purchase", "puzzle", "pyramid", "quality",
    "quantum", "quarter", "question", "quick", "quit", "rabbit", "raccoon", "radar",
    "rail", "rainbow", "random", "range", "rapid", "rather", "raven", "razor",
    "ready", "reason", "rebel", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "region", "regret", "regular", "reject", "relax",
    "release", "relief", "remain", "remember", "remind", "remove", "render", "renew",
    "repair", "repeat", "replace", "report", "require", "rescue", "resist", "resource",
    "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review",
    "reward", "rhythm", "ribbon", "rifle", "ring", "riot", "ripple", "river",
    "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie",
    "rotate", "rough", "round", "route", "royal", "rubber", "rude", "runway",
    "rural", "saddle", "sadness", "safari", "salad", "salmon", "salon", "salt",
    "salute", "sample", "satisfy", "satoshi", "sauce", "sausage", "scale", "scatter",
    "scene", "scheme", "school", "scissors", "scorpion", "scout", "script", "season",
    "secret", "section", "segment", "select", "senior", "sentence", "series", "service",
    "session", "settle", "setup", "shadow", "shaft", "shallow", "share", "shed",
    "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock",
    "shoe", "shoulder", "shove", "shrimp", "shuffle", "sibling", "sight", "silent",
    "silver", "similar", "simple", "since", "siren", "sister", "situate", "skill",
    "slender", "slice", "slim", "slogan", "slow", "small", "smile", "smoke",
    "smooth", "snack", "snake", "snap", "social", "soldier", "solution", "someone",
    "sort", "sound", "source", "south", "space", "spare", "spatial", "spawn",
    "special", "spend", "sphere", "spider", "spike", "spirit", "split", "sponge",
    "sponsor", "spoon", "sport", "spray", "spread", "spring", "square", "squeeze",
    "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
    "start", "state", "stay", "steak", "steel", "stem", "step", "stereo",
    "stick", "still", "sting", "stomach", "stone", "stool", "story", "stove",
    "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble",
    "style", "subject", "submit", "sudden", "suffer", "sugar", "suggest", "suit",
    "summer", "sun", "sunny", "super", "supply", "surface", "surge", "surprise",
    "surround", "suspect", "sustain", "swallow", "swamp", "swap", "swear", "sweet",
    "swim", "switch", "symbol", "symptom", "system", "table", "tackle", "talent",
    "target", "taste", "tattoo", "taxi", "teach", "tenant", "tennis", "test",
    "text", "thank", "theme", "theory", "thesis", "thing", "thought", "thunder",
    "ticket", "tiger", "timber", "tissue", "title", "toast", "tobacco", "today",
    "tomato", "tomorrow", "tongue", "tooth", "topic", "torch", "tornado", "tortoise",
    "total", "tourist", "toward", "tower", "town", "traffic", "train", "transfer",
    "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe",
    "trick", "trigger", "trim", "trophy", "trouble", "truck", "truly", "trumpet",
    "trust", "tumble", "turkey", "turn", "turtle", "twelve", "twenty", "twice",
    "twist", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "unfair",
    "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock",
    "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper",
    "upset", "urban", "usage", "useful", "usual", "utility", "vacant", "vacuum",
    "valley", "valve", "vanish", "vapor", "various", "vault", "velvet", "vendor",
    "venture", "venue", "verb", "verify", "version", "vessel", "veteran", "viable",
    "victory", "video", "village", "vintage", "violin", "virtual", "virus", "visa",
    "visit", "visual", "vital", "vivid", "voice", "volcano", "volume", "voyage",
    "waffle", "wagon", "walnut", "warfare", "warm", "warrior", "wash", "wasp",
    "waste", "water", "wealth", "weapon", "weather", "wedding", "weekend", "weird",
    "welcome", "west", "whale", "wheat", "wheel", "whisper", "width", "wild",
    "will", "window", "wine", "winner", "winter", "wisdom", "wolf", "woman",
    "wonder", "world", "worth", "wrap", "wrestle", "wrist", "wrong", "yellow",
    "young", "youth", "zebra", "zero", "zone",
];

pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> String {
    let mut charset: Vec<u8> = Vec::new();
    charset.extend_from_slice(LOWERCASE);
    if include_uppercase {
        charset.extend_from_slice(UPPERCASE);
    }
    if include_numbers {
        charset.extend_from_slice(DIGITS);
    }
    if include_symbols {
        charset.extend_from_slice(SYMBOLS);
    }

    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = !include_uppercase || password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = !include_numbers || password.chars().any(|c| c.is_ascii_digit());
    let has_symbol =
        !include_symbols || password.chars().any(|c| SYMBOLS.contains(&(c as u8)));

    if length >= 4 && (!has_lower || !has_upper || !has_digit || !has_symbol) {
        return generate_password(length, include_uppercase, include_numbers, include_symbols);
    }

    password
}

pub fn generate_passphrase(words: usize, separator: &str) -> String {
    let mut rng = rand::thread_rng();
    let chosen: Vec<&str> = (0..words)
        .map(|_| {
            let idx = rng.gen_range(0..WORDLIST.len());
            WORDLIST[idx]
        })
        .collect();
    chosen.join(separator)
