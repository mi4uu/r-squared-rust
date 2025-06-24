//! Brain key implementation for deterministic key generation

use crate::error::{EccError, EccResult};
use crate::ecc::{PrivateKey, PublicKey, hash};
use sha2::{Sha256, Digest};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use rand::{Rng, thread_rng};

/// A brain key for deterministic key generation from mnemonic phrases
#[derive(Clone, Debug)]
pub struct BrainKey {
    /// The mnemonic words
    words: String,
    /// Normalized words for consistent key derivation
    normalized_words: String,
}

impl BrainKey {
    /// Create a brain key from words
    pub fn from_words(words: &str) -> EccResult<Self> {
        let normalized_words = Self::normalize_words(words);
        
        if normalized_words.split_whitespace().count() < 12 {
            return Err(EccError::KeyDerivationFailed {
                reason: "Brain key must have at least 12 words".to_string(),
            });
        }
        
        Ok(Self {
            words: words.to_string(),
            normalized_words,
        })
    }

    /// Generate a random brain key with specified word count
    pub fn generate(word_count: usize) -> EccResult<Self> {
        if word_count < 12 || word_count > 24 {
            return Err(EccError::KeyDerivationFailed {
                reason: "Word count must be between 12 and 24".to_string(),
            });
        }

        let dictionary = Self::get_dictionary();
        let mut rng = thread_rng();
        let mut words = Vec::new();
        
        for _ in 0..word_count {
            let index = rng.gen_range(0..dictionary.len());
            words.push(dictionary[index]);
        }
        
        let words_str = words.join(" ");
        Self::from_words(&words_str)
    }

    /// Get the words
    pub fn words(&self) -> &str {
        &self.words
    }

    /// Get the normalized words
    pub fn normalized_words(&self) -> &str {
        &self.normalized_words
    }

    /// Derive a private key from the brain key
    pub fn to_private_key(&self) -> EccResult<PrivateKey> {
        self.to_private_key_with_sequence(0)
    }

    /// Derive a private key with a sequence number
    pub fn to_private_key_with_sequence(&self, sequence: u32) -> EccResult<PrivateKey> {
        let mut key_material = Vec::new();
        key_material.extend_from_slice(self.normalized_words.as_bytes());
        key_material.extend_from_slice(&sequence.to_be_bytes());
        
        // Use PBKDF2 for key derivation
        let mut derived_key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(
            self.normalized_words.as_bytes(),
            &sequence.to_be_bytes(),
            4096, // iterations
            &mut derived_key,
        );
        
        PrivateKey::from_bytes(&derived_key)
    }

    /// Derive a public key from the brain key
    pub fn to_public_key(&self) -> EccResult<PublicKey> {
        let private_key = self.to_private_key()?;
        Ok(private_key.public_key()?)
    }

    /// Validate the brain key words against dictionary
    pub fn validate(&self) -> EccResult<bool> {
        let dictionary = Self::get_dictionary();
        let words: Vec<&str> = self.normalized_words.split_whitespace().collect();
        
        for word in words {
            if !dictionary.contains(&word) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    /// Normalize words for consistent processing
    fn normalize_words(words: &str) -> String {
        words
            .trim()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
    }

    /// Get a simple dictionary for brain key generation
    fn get_dictionary() -> Vec<&'static str> {
        vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
            "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
            "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
            "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing",
            "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle",
            "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
            "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve",
            "april", "arcade", "arch", "arctic", "area", "arena", "argue", "arm",
            "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow",
            "art", "article", "artist", "artwork", "ask", "aspect", "assault", "asset",
            "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
            "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
            "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful",
            "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance",
            "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
            "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty",
            "because", "become", "beef", "before", "begin", "behave", "behind", "believe",
            "below", "belt", "bench", "benefit", "best", "betray", "better", "between",
            "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth",
            "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
            "blind", "blood", "blossom", "blow", "blue", "blur", "blush", "board",
            "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost",
            "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
            "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick",
            "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
            "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo",
            "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger",
            "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
            "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera",
            "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
            "canyon", "capable", "capital", "captain", "car", "carbon", "card", "care",
            "career", "careful", "careless", "cargo", "carpet", "carry", "cart", "case",
            "cash", "casino", "cast", "casual", "cat", "catalog", "catch", "category",
            "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement",
            "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change",
            "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese",
            "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
            "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
            "citizen", "city", "civil", "claim", "clamp", "clarify", "claw", "clay",
            "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic",
            "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club",
            "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee",
            "coil", "coin", "collect", "color", "column", "combine", "come", "comfort",
            "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect",
            "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
            "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple",
            "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram",
            "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
            "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch",
            "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
            "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain",
            "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp",
            "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
            "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease",
            "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand",
            "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth",
            "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy",
            "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond",
            "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma",
            "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish",
            "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy",
            "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey",
            "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama",
            "drape", "draw", "dream", "dress", "drift", "drill", "drink", "drip",
            "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during",
            "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early",
            "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy",
            "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow",
            "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
            "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty",
            "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce",
            "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll",
            "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip",
            "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay",
            "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve",
            "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute",
            "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
            "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye",
            "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall",
            "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm",
            "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature",
            "february", "federal", "fee", "feed", "feel", "female", "fence", "festival",
            "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
            "fill", "film", "filter", "final", "find", "fine", "finger", "finish",
            "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix",
            "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip",
            "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
            "focus", "fog", "foil", "fold", "follow", "food", "foot", "force",
            "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster",
            "found", "fox", "frame", "frequent", "fresh", "friend", "fringe", "frog",
            "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny",
            "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game",
            "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp",
            "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle",
            "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe",
            "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse",
            "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess",
            "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
            "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great",
            "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt",
            "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit",
            "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard",
            "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
            "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen",
            "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history",
            "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey",
            "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel",
            "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred",
            "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice",
            "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness",
            "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse",
            "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry",
            "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury",
            "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside",
            "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve",
            "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar",
            "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join",
            "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior",
            "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick",
            "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite",
            "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label",
            "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large",
            "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit",
            "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left",
            "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens",
            "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license",
            "life", "lift", "light", "like", "limb", "limit", "link", "lion",
            "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster",
            "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud",
            "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch",
            "luxury", "lying", "machine", "mad", "magic", "magnet", "maid", "mail",
            "main", "major", "make", "mammal", "man", "manage", "mandate", "mango",
            "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market",
            "marriage", "mask", "mass", "master", "match", "material", "math", "matrix",
            "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic",
            "medal", "media", "melody", "melt", "member", "memory", "mention", "menu",
            "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method",
            "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor",
            "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed",
            "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey",
            "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother",
            "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin",
            "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual",
            "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty",
            "nation", "nature", "near", "neck", "need", "needle", "neglect", "neighbor",
            "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never",
            "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle",
            "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel",
            "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
            "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october",
            "odor", "off", "offer", "office", "often", "oil", "okay", "old",
            "olive", "olympic", "omit", "once", "one", "onion", "online", "only",
            "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard",
            "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other",
            "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own",
            "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair",
            "palace", "pale", "palm", "panda", "panel", "panic", "panther", "paper",
            "parade", "parent", "park", "parrot", "part", "party", "pass", "patch",
            "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace",
            "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
            "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase",
            "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill",
            "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place",
            "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug",
            "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond",
            "pony", "pool", "popular", "portion", "position", "possible", "post", "potato",
            "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer",
            "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print",
            "priority", "prison", "private", "prize", "problem", "process", "produce", "profit",
            "program", "project", "promote", "proof", "property", "prosper", "protect", "proud",
            "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch",
            "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put",
            "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quiet",
            "quilt", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack",
            "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch",
            "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw",
            "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive",
            "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
            "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain",
            "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair",
            "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource",
            "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review",
            "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge",
            "rifle", "right", "rigid", "ring", "riot", "ripple", "rise", "risk",
            "ritual", "rival", "river", "road", "roast", "rob", "robot", "robust",
            "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough",
            "round", "route", "royal", "rubber", "rude", "rug", "rule", "run",
            "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad",
            "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy",
            "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare",
            "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout",
            "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat",
            "second", "secret", "section", "security", "seed", "seek", "segment", "select",
            "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session",
            "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed",
            "shell", "sheriff", "shield", "shift", "shine", "ship", "shirt", "shock",
            "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug",
            "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign",
            "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing",
            "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski",
            "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender",
            "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush",
            "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
            "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft",
            "solar", "sold", "soldier", "solid", "solution", "solve", "someone", "song",
            "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south",
            "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell",
            "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
            "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring",
            "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage",
            "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel",
            "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach",
            "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong",
            "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway",
            "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer",
            "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface",
            "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp",
            "swap", "swear", "sweet", "swift", "swim", "swing", "switch", "sword",
            "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail",
            "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo",
            "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent",
            "term", "test", "text", "thank", "that", "theme", "then", "theory",
            "there", "they", "thing", "this", "thought", "three", "thrive", "throw",
            "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time",
            "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
            "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone",
            "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch",
            "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
            "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap",
            "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe",
            "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true",
            "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble",
            "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice",
            "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable",
            "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy",
            "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual",
            "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban",
            "urge", "usage", "use", "used", "useful", "useless", "usual", "utility",
            "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish",
            "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture",
            "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable",
            "vibe", "vicious", "victory", "video", "view", "village", "vintage", "violin",
            "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal",
            "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon",
            "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior",
            "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon",
            "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome",
            "west", "wet", "what", "wheat", "wheel", "when", "where", "whip",
            "whisper", "wide", "width", "wife", "wild", "will", "win", "window",
            "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise",
            "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word",
            "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
            "write", "wrong", "yard"
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brain_key_from_words() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let brain_key = BrainKey::from_words(words).unwrap();
        assert_eq!(brain_key.words(), words);
    }

    #[test]
    fn test_brain_key_generation() {
        let brain_key = BrainKey::generate(12).unwrap();
        let words: Vec<&str> = brain_key.words().split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_brain_key_to_private_key() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let brain_key = BrainKey::from_words(words).unwrap();
        let private_key = brain_key.to_private_key().unwrap();
        let _public_key = private_key.public_key();
    }

    #[test]
    fn test_brain_key_sequence_derivation() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let brain_key = BrainKey::from_words(words).unwrap();
        
        let key1 = brain_key.to_private_key_with_sequence(0).unwrap();
        let key2 = brain_key.to_private_key_with_sequence(1).unwrap();
        
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_brain_key_validation() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let brain_key = BrainKey::from_words(words).unwrap();
        assert!(brain_key.validate().unwrap());
        
        let invalid_words = "invalid words that are not in dictionary";
        let invalid_brain_key = BrainKey::from_words(invalid_words).unwrap();
        assert!(!invalid_brain_key.validate().unwrap());
    }

    #[test]
    fn test_brain_key_normalization() {
        let words1 = "  ABANDON   abandon   ABANDON  ";
        let words2 = "abandon abandon abandon";
        
        let brain_key1 = BrainKey::from_words(words1).unwrap();
        let brain_key2 = BrainKey::from_words(words2).unwrap();
        
        assert_eq!(brain_key1.normalized_words(), brain_key2.normalized_words());
    }
}