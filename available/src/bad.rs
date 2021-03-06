pub const BADTLDS: &[&str] = &[
    "abarth",
    "abbvie",
    "abc",
    "able",
    "abudhabi",
    "ad",
    "adac",
    "aetna",
    "afamilycompany",
    "africa",
    "agakhan",
    "ai",
    "aigo",
    "airbus",
    "akdn",
    "al",
    "alfaromeo",
    "alibaba",
    "alipay",
    "allstate",
    "ally",
    "alstom",
    "americanexpress",
    "americanfamily",
    "amex",
    "amfam",
    "analytics",
    "anquan",
    "anz",
    "ao",
    "aol",
    "aq",
    "ar",
    "arab",
    "art",
    "asda",
    "athleta",
    "audible",
    "auspost",
    "avianca",
    "aws",
    "az",
    "ba",
    "baby",
    "baidu",
    "banamex",
    "bananarepublic",
    "barefoot",
    "baseball",
    "basketball",
    "bb",
    "bbt",
    "bcg",
    "bd",
    "beauty",
    "bestbuy",
    "bf",
    "bh",
    "blanco",
    "blockbuster",
    "blog",
    "bm",
    "bofa",
    "booking",
    "bosch",
    "boston",
    "box",
    "bs",
    "bt",
    "bv",
    "calvinklein",
    "cam",
    "capitalone",
    "case",
    "caseih",
    "catholic",
    "cbre",
    "cbs",
    "cg",
    "chase",
    "chintai",
    "chrysler",
    "citadel",
    "citi",
    "ck",
    "clinique",
    "comcast",
    "compare",
    "contact",
    "cookingchannel",
    "coupon",
    "cruise",
    "cu",
    "cv",
    "cw",
    "cy",
    "data",
    "dds",
    "deal",
    "dealer",
    "deloitte",
    "dhl",
    "discover",
    "dish",
    "diy",
    "dj",
    "do",
    "doctor",
    "dodge",
    "dot",
    "dtv",
    "dubai",
    "duck",
    "dunlop",
    "duns",
    "dupont",
    "dvr",
    "eco",
    "edeka",
    "eg",
    "epost",
    "er",
    "ericsson",
    "es",
    "esurance",
    "et",
    "etisalat",
    "extraspace",
    "farmers",
    "fedex",
    "ferrari",
    "fiat",
    "fidelity",
    "fido",
    "fire",
    "fk",
    "flickr",
    "flir",
    "fm",
    "food",
    "foodnetwork",
    "ford",
    "fox",
    "free",
    "fresenius",
    "frontdoor",
    "frontier",
    "ftr",
    "fujitsu",
    "fujixerox",
    "fun",
    "gallo",
    "gallup",
    "games",
    "gap",
    "gb",
    "ge",
    "george",
    "gf",
    "gh",
    "glade",
    "gm",
    "gmbh",
    "gn",
    "godaddy",
    "goodhands",
    "goodyear",
    "gp",
    "gr",
    "grocery",
    "gt",
    "gu",
    "guardian",
    "gw",
    "hair",
    "hbo",
    "hdfc",
    "hdfcbank",
    "health",
    "helsinki",
    "hgtv",
    "hisamitsu",
    "hkt",
    "homegoods",
    "homesense",
    "honeywell",
    "hospital",
    "hot",
    "hotels",
    "hughes",
    "hyatt",
    "ieee",
    "ikano",
    "imamat",
    "imdb",
    "intel",
    "intuit",
    "iselect",
    "ismaili",
    "itv",
    "iveco",
    "jcp",
    "jeep",
    "jio",
    "jm",
    "jmp",
    "jnj",
    "jo",
    "jpmorgan",
    "juniper",
    "kerryhotels",
    "kerrylogistics",
    "kerryproperties",
    "kfh",
    "kh",
    "kindle",
    "km",
    "kn",
    "kosher",
    "kp",
    "kpmg",
    "kpn",
    "kuokgroup",
    "kw",
    "ladbrokes",
    "lamer",
    "lancia",
    "lancome",
    "lanxess",
    "latino",
    "lb",
    "lefrak",
    "lego",
    "lifeinsurance",
    "lilly",
    "lincoln",
    "lipsy",
    "living",
    "llc",
    "locker",
    "locus",
    "loft",
    "lpl",
    "lplfinancial",
    "lr",
    "ls",
    "lundbeck",
    "macys",
    "makeup",
    "map",
    "marshalls",
    "maserati",
    "mattel",
    "mc",
    "mckinsey",
    "merckmsd",
    "metlife",
    "mh",
    "mil",
    "mint",
    "mit",
    "mitsubishi",
    "mlb",
    "mls",
    "mm",
    "mo",
    "mobile",
    "mobily",
    "monster",
    "mopar",
    "moto",
    "mp",
    "mq",
    "mr",
    "msd",
    "mt",
    "mutual",
    "mv",
    "mw",
    "nab",
    "nationwide",
    "natura",
    "nba",
    "ne",
    "netflix",
    "newholland",
    "next",
    "nextdirect",
    "nfl",
    "ni",
    "nike",
    "nikon",
    "nissay",
    "northwesternmutual",
    "now",
    "nowtv",
    "np",
    "nr",
    "observer",
    "off",
    "olayan",
    "olayangroup",
    "oldnavy",
    "ollo",
    "onyourside",
    "open",
    "origins",
    "ott",
    "pa",
    "panasonic",
    "pars",
    "passagens",
    "pay",
    "pccw",
    "pfizer",
    "pg",
    "ph",
    "phd",
    "phone",
    "pid",
    "pioneer",
    "pk",
    "pn",
    "pnc",
    "politie",
    "pramerica",
    "prime",
    "progressive",
    "promo",
    "pru",
    "prudential",
    "pwc",
    "py",
    "quest",
    "qvc",
    "radio",
    "raid",
    "realestate",
    "redumbrella",
    "reliance",
    "rexroth",
    "richardli",
    "rightathome",
    "ril",
    "rmit",
    "rogers",
    "rugby",
    "safety",
    "samsclub",
    "sas",
    "save",
    "sbi",
    "schaeffler",
    "scjohnson",
    "sd",
    "search",
    "secure",
    "select",
    "ses",
    "shangrila",
    "shaw",
    "shell",
    "shop",
    "shopping",
    "shouji",
    "showtime",
    "silk",
    "sina",
    "sj",
    "skin",
    "sling",
    "smart",
    "softbank",
    "song",
    "sport",
    "spot",
    "sr",
    "srt",
    "staples",
    "star",
    "statebank",
    "statefarm",
    "storage",
    "store",
    "stream",
    "sv",
    "swiftcover",
    "sz",
    "talk",
    "taobao",
    "target",
    "td",
    "tdk",
    "telecity",
    "teva",
    "tiaa",
    "tiffany",
    "tj",
    "tjmaxx",
    "tjx",
    "tkmaxx",
    "tmall",
    "total",
    "travelchannel",
    "travelersinsurance",
    "trv",
    "tt",
    "tube",
    "tunes",
    "tushu",
    "tvs",
    "ubank",
    "uconnect",
    "unicom",
    "ups",
    "va",
    "vanguard",
    "vi",
    "vig",
    "viking",
    "visa",
    "vivo",
    "vn",
    "volkswagen",
    "volvo",
    "vuelos",
    "walmart",
    "wanggou",
    "warman",
    "watches",
    "weather",
    "weatherchannel",
    "weber",
    "weibo",
    "winners",
    "wolterskluwer",
    "woodside",
    "wow",
    "xfinity",
    "xihuan",
    "xn--1ck2e1b",
    "xn--2scrj9c",
    "xn--3hcrj9c",
    "xn--3oq18vl8pn36a",
    "xn--45br5cyl",
    "xn--54b7fta0cc",
    "xn--5su34j936bgsg",
    "xn--5tzm5g",
    "xn--80aqecdr1a",
    "xn--8y0a063a",
    "xn--90ae",
    "xn--9krt00a",
    "xn--bck1b9a5dre4c",
    "xn--cck2b3b",
    "xn--e1a4c",
    "xn--eckvdtc9d",
    "xn--fct429k",
    "xn--fzys8d69uvgm",
    "xn--g2xx48c",
    "xn--gckr3f0f",
    "xn--gk3at1e",
    "xn--h2breg3eve",
    "xn--h2brj9c8c",
    "xn--jlq61u9w7b",
    "xn--jvr189m",
    "xn--kpu716f",
    "xn--l1acc",
    "xn--mgba7c0bbn0a",
    "xn--mgbaakc7dvf",
    "xn--mgbai9azgqp6j",
    "xn--mgbayh7gpa",
    "xn--mgbb9fbpob",
    "xn--mgbbh1a",
    "xn--mgbc0a9azcg",
    "xn--mgbca7dzdo",
    "xn--mgbgu82a",
    "xn--mgbi4ecexp",
    "xn--mgbpl2fh",
    "xn--mgbt3dhd",
    "xn--mix891f",
    "xn--ngbe9e0a",
    "xn--ngbrx",
    "xn--otu796d",
    "xn--pbt977c",
    "xn--pgbs0dh",
    "xn--qxam",
    "xn--rovu88b",
    "xn--rvc1e0am3e",
    "xn--tiq49xqyj",
    "xn--w4r85el8fhu5dnra",
    "xn--w4rs40l",
    "yahoo",
    "ye",
    "you",
    "yun",
    "za",
    "zappos",
    "zippo",
    "zw",
    "bg",
    "bo",
    "cd",
    "ch",
    "ec",
    "fo",
    "hm",
    "li",
    "ml",
    "my",
    "pf",
    "pt",
    "ug",
    "vu",
    "xn--3e0b707e",
    "xn--mgbx4cd0ab",
];
