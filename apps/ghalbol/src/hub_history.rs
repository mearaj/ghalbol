//! Hub navigation history stack.

const MAX_HISTORY_KEY_CHARS: usize = 256;
const MAX_HISTORY_PAGE_CHARS: usize = 64;

fn clamp_history_entry(mut entry: HubHistoryEntry) -> HubHistoryEntry {
    if entry.conversation_key.chars().count() > MAX_HISTORY_KEY_CHARS {
        entry.conversation_key = entry
            .conversation_key
            .chars()
            .take(MAX_HISTORY_KEY_CHARS)
            .collect();
    }
    if entry.page.chars().count() > MAX_HISTORY_PAGE_CHARS {
        entry.page = entry.page.chars().take(MAX_HISTORY_PAGE_CHARS).collect();
    }
    entry
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct HubHistoryEntry {
    pub(crate) hub_tab: u8,
    pub(crate) narrow_show_room: bool,
    pub(crate) conversation_key: String,
    /// Sheet id (`invite`, `password`, `lang`, …). Empty = hub chrome only.
    pub(crate) page: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HubHistoryStack {
    pub(crate) entries: Vec<HubHistoryEntry>,
    /// Cursor into `entries` (browser-style; forward keeps truncated tail until a new navigate).
    pub(crate) index: usize,
}

impl HubHistoryStack {
    pub(crate) fn reset(&mut self, entry: HubHistoryEntry) {
        self.entries.clear();
        self.entries.push(clamp_history_entry(entry));
        self.index = 0;
    }

    pub(crate) fn replace_top(&mut self, entry: HubHistoryEntry) {
        let entry = clamp_history_entry(entry);
        if self.entries.is_empty() {
            self.entries.push(entry);
            self.index = 0;
            return;
        }
        if self.index >= self.entries.len() {
            self.index = self.entries.len() - 1;
        }
        self.entries[self.index] = entry.clone();
        if self.index > 0 && self.entries[self.index - 1] == entry {
            self.entries.remove(self.index);
            self.index -= 1;
        }
    }

    pub(crate) fn record(&mut self, entry: HubHistoryEntry) {
        let entry = clamp_history_entry(entry);
        if self.entries.get(self.index) == Some(&entry) {
            return;
        }
        if self.entries.is_empty() {
            self.entries.push(entry);
            self.index = 0;
            return;
        }
        // New branch discards anything ahead of the cursor (browser navigate).
        self.entries.truncate(self.index + 1);
        self.entries.push(entry);
        self.index = self.entries.len() - 1;
        const MAX: usize = 64;
        while self.entries.len() > MAX {
            self.entries.remove(0);
            self.index = self.index.saturating_sub(1);
        }
    }

    pub(crate) fn go_back(&mut self) -> Option<HubHistoryEntry> {
        if self.index == 0 || self.entries.is_empty() {
            return None;
        }
        self.index -= 1;
        self.entries.get(self.index).cloned()
    }

    pub(crate) fn can_go_back(&self) -> bool {
        self.index > 0 && !self.entries.is_empty()
    }

    pub(crate) fn go_forward(&mut self) -> Option<HubHistoryEntry> {
        if self.index + 1 >= self.entries.len() {
            return None;
        }
        self.index += 1;
        self.entries.get(self.index).cloned()
    }
}



#[cfg(test)]
mod hub_history_tests {
    use super::{HubHistoryEntry, HubHistoryStack, MAX_HISTORY_KEY_CHARS};

    fn entry(tab: u8, page: &str) -> HubHistoryEntry {
        HubHistoryEntry {
            hub_tab: tab,
            narrow_show_room: false,
            conversation_key: String::new(),
            page: page.into(),
        }
    }

    #[test]
    fn back_walks_sheet_then_tab() {
        let mut h = HubHistoryStack::default();
        h.reset(entry(0, ""));
        h.record(entry(2, ""));
        h.record(entry(2, "lang"));
        assert!(h.can_go_back());
        assert_eq!(h.go_back().unwrap().page, "");
        assert_eq!(h.go_back().unwrap().hub_tab, 0);
        assert!(!h.can_go_back());
    }

    #[test]
    fn replace_top_collapses_duplicate() {
        let mut h = HubHistoryStack::default();
        h.reset(entry(0, ""));
        h.record(entry(0, "invite"));
        h.replace_top(entry(0, ""));
        assert_eq!(h.entries.len(), 1);
        assert_eq!(h.index, 0);
    }

    #[test]
    fn room_then_sheet_back_restores_room() {
        let mut h = HubHistoryStack::default();
        h.reset(HubHistoryEntry {
            hub_tab: 0,
            narrow_show_room: false,
            conversation_key: String::new(),
            page: String::new(),
        });
        h.record(HubHistoryEntry {
            hub_tab: 0,
            narrow_show_room: true,
            conversation_key: "aabb".into(),
            page: String::new(),
        });
        h.record(HubHistoryEntry {
            hub_tab: 0,
            narrow_show_room: true,
            conversation_key: "aabb".into(),
            page: "invite".into(),
        });
        let prev = h.go_back().unwrap();
        assert_eq!(prev.page, "");
        assert!(prev.narrow_show_room);
        assert_eq!(prev.conversation_key, "aabb");
    }

    #[test]
    fn contacts_tab_back_restores_chats_room() {
        let mut h = HubHistoryStack::default();
        h.reset(HubHistoryEntry {
            hub_tab: 0,
            narrow_show_room: true,
            conversation_key: "peer1".into(),
            page: String::new(),
        });
        // hub_tab 1 = Contacts peer (was Identity under the old More/Identity hub).
        h.record(HubHistoryEntry {
            hub_tab: 1,
            narrow_show_room: false,
            conversation_key: "peer1".into(),
            page: String::new(),
        });
        let prev = h.go_back().unwrap();
        assert_eq!(prev.hub_tab, 0);
        assert!(prev.narrow_show_room);
        assert_eq!(prev.conversation_key, "peer1");
    }

    #[test]
    fn record_clamps_oversized_conversation_key() {
        let mut h = HubHistoryStack::default();
        let mut e = entry(0, "");
        e.conversation_key = "a".repeat(MAX_HISTORY_KEY_CHARS + 40);
        h.record(e);
        assert_eq!(
            h.entries[0].conversation_key.chars().count(),
            MAX_HISTORY_KEY_CHARS
        );
    }

    #[test]
    fn record_after_back_discards_forward_tail() {
        let mut h = HubHistoryStack::default();
        h.reset(entry(0, ""));
        h.record(entry(0, "lang"));
        h.record(entry(0, "invite"));
        assert_eq!(h.go_back().unwrap().page, "lang");
        h.record(entry(0, "password"));
        assert_eq!(h.entries.len(), 3);
        assert_eq!(h.entries.last().unwrap().page, "password");
        assert!(h.go_forward().is_none());
    }

    #[test]
    fn forward_after_back_restores_sheet() {
        let mut h = HubHistoryStack::default();
        h.reset(entry(0, ""));
        h.record(entry(0, "lang"));
        assert_eq!(h.go_back().unwrap().page, "");
        assert_eq!(h.go_forward().unwrap().page, "lang");
    }
}

