//! The ssh config screen's state: which step the user is at, and what the outside
//! world said at the last one.
//!
//! Pure state, like the rest of the app's logic: reading the ssh config, writing
//! the export and saving hosts are requests (see [`super::effects`]), and this
//! only holds what came back. Nothing is saved or written from here.

use super::effects::{ExportDone, ExportPlan, ImportPreview};
use crate::ssh::export::TargetState;

/// Where the user is.
#[derive(Debug)]
pub enum Stage {
    /// The two things that can be done.
    Menu,
    /// What importing would do, and the question whether to do it.
    ImportPreview(ImportPreview),
    /// The import was saved: what was added, what was left out and why.
    Imported(ImportPreview),
    /// Where the export would write, and the question whether to write it.
    ExportPlan {
        plan: ExportPlan,
        /// How many hosts are exported.
        hosts: usize,
    },
    /// The export was written, and what is left for the user to do.
    Exported { done: ExportDone, hosts: usize },
}

#[derive(Debug)]
pub struct SshConfigScreen {
    stage: Stage,
}

impl SshConfigScreen {
    pub fn new() -> Self {
        SshConfigScreen { stage: Stage::Menu }
    }

    pub fn stage(&self) -> &Stage {
        &self.stage
    }

    pub fn show(&mut self, stage: Stage) {
        self.stage = stage;
    }

    /// The import that was being asked about has been saved.
    pub fn mark_imported(&mut self) {
        if let Stage::ImportPreview(preview) = std::mem::replace(&mut self.stage, Stage::Menu) {
            self.stage = Stage::Imported(preview);
        }
    }

    /// Back to the two choices.
    pub fn menu(&mut self) {
        self.stage = Stage::Menu;
    }

    /// How many hosts the import being shown would add: what pressing the
    /// confirming key does something for. Zero when nothing is being asked.
    pub fn importable(&self) -> usize {
        match &self.stage {
            Stage::ImportPreview(preview) => preview.report.imported.len(),
            _ => 0,
        }
    }

    /// Whether the export being shown may be written. A file that Bifrost did not
    /// make is never replaced, so the question is not asked about it.
    pub fn exportable(&self) -> bool {
        matches!(
            &self.stage,
            Stage::ExportPlan { plan, .. } if plan.state != TargetState::NotGenerated
        )
    }
}

impl Default for SshConfigScreen {
    fn default() -> Self {
        Self::new()
    }
}
