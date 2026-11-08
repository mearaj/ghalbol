//! Helpers for compact phrase-sheet tables.

macro_rules! sheet {
    ($($k:literal => $v:literal),* $(,)?) => { &[ $(($k, $v)),* ] };
}
