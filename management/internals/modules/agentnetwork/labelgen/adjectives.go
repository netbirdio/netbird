package labelgen

// adjectives is the descriptor half of a generated label. It pairs with the
// noun pool in words.go to form `<adjective>-<noun>` labels, and is kept
// separate because words.go is almost entirely nouns — drawing both halves
// from it produced unreadable pairs like "millet-hammock". Entries are
// lowercase ASCII, 4-12 chars, free of hyphens and digits, screened for
// offensive/brand/region-specific terms, and disjoint from the noun pool
// (enforced by TestAdjectives_AreDisjointFromNouns).
var adjectives = []string{
	"able", "active", "adept", "agile", "airy", "alert", "amiable", "ample",
	"ancient", "ardent", "artful", "astute", "balmy", "blithe", "bold", "bonny",
	"brave", "breezy", "brisk", "bubbly", "buoyant", "bushy", "candid", "canny",
	"cheery", "chilly", "chipper", "chunky", "civil", "classic", "clever", "comely",
	"compact", "cordial", "cosmic", "courtly", "crafty", "creamy", "crisp", "cuddly",
	"curious", "dainty", "dapper", "daring", "dashing", "deft", "dewy", "diligent",
	"downy", "dreamy", "dulcet", "durable", "dusky", "eager", "earnest", "earthy",
	"easy", "elated", "elegant", "epic", "fabled", "faithful", "fancy", "fearless",
	"feisty", "fervent", "fleet", "fluffy", "fond", "frisky", "frosty", "gallant",
	"genial", "genteel", "gentle", "giddy", "gilded", "glad", "glassy", "gleaming",
	"glossy", "graceful", "grand", "grainy", "hale", "hardy", "hearty", "hefty",
	"honest", "hopeful", "humble", "hushed", "immense", "jaunty", "jolly", "jovial",
	"joyful", "jubilant", "keen", "kindly", "kindred", "lanky", "leafy", "limber",
	"lively", "lofty", "loyal", "lucent", "lucid", "luminous", "lush", "maroon",
	"mellow", "merry", "mighty", "mindful", "mirthful", "misty", "modest", "muted",
	"nifty", "nimble", "noble", "patient", "peaceful", "pearly", "peppy", "perky",
	"petite", "placid", "playful", "pleasant", "plucky", "plush", "polite", "posh",
	"prancing", "pristine", "prompt", "proud", "prudent", "quaint", "quick", "quirky",
	"radiant", "ready", "regal", "restful", "robust", "rosy", "ruddy", "rugged",
	"sandy", "satin", "saucy", "savvy", "sedate", "serene", "shady", "shiny",
	"silken", "silky", "sincere", "sleek", "slender", "smart", "smooth", "snappy",
	"snug", "soaring", "sparkly", "spiffy", "spirited", "sprightly", "spry", "stalwart",
	"stately", "steady", "sterling", "stoic", "stormy", "stout", "sturdy", "sunlit",
	"supple", "svelte", "tawny", "tender", "tidy", "timeless", "trusty", "upbeat",
	"urbane", "valiant", "vast", "vernal", "vibrant", "vintage", "whimsy", "willing",
	"windy", "winsome", "wintry", "witty", "worthy", "zesty", "zippy",
}
