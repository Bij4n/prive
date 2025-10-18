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
