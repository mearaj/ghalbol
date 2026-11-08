//! Sheet copy for languages that ship a full chrome table.
//! Languages without a row fall back to English via `i18n::phrase`.

#[macro_use]
mod macros;

mod asian;
mod european;
mod indian_extra;
mod indic;

use asian::*;
use european::*;
use indian_extra::*;
use indic::*;

pub fn row(lang: &str) -> Option<&'static [(&'static str, &'static str)]> {
    Some(match lang {
        "pt" => PT,
        "it" => IT,
        "nl" => NL,
        "pl" => PL,
        "uk" => UK,
        "ru" => RU,
        "fa" => FA,
        "tr" => TR,
        "ja" => JA,
        "ko" => KO,
        "vi" => VI,
        "th" => TH,
        "id" => ID,
        "sw" => SW,
        "bn" => BN,
        "as" => AS,
        "brx" => BRX,
        "doi" => DOI,
        "gu" => GU,
        "kn" => KN,
        "ks" => KS,
        "kok" => KOK,
        "ml" => ML,
        "mni" => MNI,
        "mr" => MR,
        "mai" => MAI,
        "ne" => NE,
        "or" => OR,
        "pa" => PA,
        "sa" => SA,
        "sat" => SAT,
        "sd" => SD,
        "ta" => TA,
        "te" => TE,
        "ur" => UR,
        "bho" => BHO,
        "hne" => HNE,
        "lus" => LUS,
        "kha" => KHA,
        "grt" => GRT,
        "trp" => TRP,
        "lep" => LEP,
        _ => return None,
    })
}
