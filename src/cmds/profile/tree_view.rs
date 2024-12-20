use std::time::Duration;
use strum::IntoEnumIterator;
use tui_realm_stdlib::Phantom;
use tui_realm_treeview::{Node, Tree, TreeView, TREE_CMD_CLOSE, TREE_CMD_OPEN};
use tuirealm::terminal::CrosstermTerminalAdapter;
use tuirealm::{
    application::PollStrategy,
    command::{Cmd, CmdResult, Direction},
    event::{Event, Key, KeyEvent, KeyModifiers},
    props::{Alignment, BorderType, Borders, Color, Style},
    terminal::TerminalBridge,
    Application, Component, EventListenerCfg, MockComponent, NoUserEvent, State, StateValue, Sub,
    SubClause, SubEventClause, Update,
};

use crate::cmds::profile::process::{Process, ProcessStat, TotalProcessStat};

#[derive(Debug, PartialEq)]
pub enum Msg {
    AppClose,
    OpenProcess(String),
    None,
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum Id {
    ProcessTree,
    GlobalListener,
}

#[allow(dead_code)]
struct Model {
    app: Application<Id, Msg, NoUserEvent>,
    process_vec: Vec<Process>,
    tree: Tree<String>,
    redraw: bool,
    quit: bool,
    terminal: TerminalBridge<CrosstermTerminalAdapter>,
}

fn newkey(pid: u32, key: &mut u64) -> String {
    let k = *key;
    *key += 1;
    format!("{}_{}", pid, k)
}

impl Model {
    fn new(processes: Vec<Process>) -> Self {
        let mut app = Application::init(
            EventListenerCfg::default().crossterm_input_listener(Duration::from_millis(10), 10),
        );
        let title = format!("Processes: {}", processes.len()).to_string();
        let mut scroll = processes.len();
        let tree = Tree::new(Self::processes_to_nodes(&processes));
        scroll /= 4;
        app.mount(
            Id::ProcessTree,
            Box::new(ProcessTree::new(tree.clone(), None, title, scroll)),
            vec![],
        )
        .expect("Failed to mount process tree");
        app.mount(
            Id::GlobalListener,
            Box::new(GlobalListener::default()),
            vec![Sub::new(
                SubEventClause::Keyboard(KeyEvent {
                    code: Key::Esc,
                    modifiers: KeyModifiers::NONE,
                }),
                SubClause::Always,
            )],
        )
        .expect("Failed to mount GlobalListener");
        app.active(&Id::ProcessTree)
            .expect("Failed to set focus to ProcessTree");
        Model {
            app,
            process_vec: processes,
            tree,
            quit: false,
            redraw: true,
            terminal: TerminalBridge::init_crossterm().expect("Failed to init terminal"),
        }
    }

    fn view(&mut self) {
        let _ = self.terminal.raw_mut().draw(|f| {
            self.app.view(&Id::ProcessTree, f, f.area());
        });
    }

    fn process_to_nodes(pnode: &mut Node<String>, process: &Process) {
        let mut key: u64 = 0;
        let pid = process.pid;
        pnode.add_child(Node::new(
            newkey(pid, &mut key),
            format!("Cgroup ID: {}", process.cgid).to_string(),
        ));

        let mut pstat = Node::new(newkey(pid, &mut key), "Process Stats".to_string());
        for stat in ProcessStat::iter() {
            let mut snode = Node::new(newkey(pid, &mut key), stat.to_string());
            for r in process.runs.iter() {
                snode.add_child(Node::new(
                    newkey(pid, &mut key),
                    format!("{}: {}", r.start_time.format("%H:%M:%S"), r.stat_str(&stat)),
                ));
            }
            pstat.add_child(snode);
        }
        pnode.add_child(pstat);

        let mut pstat = Node::new(newkey(pid, &mut key), "Total Stats".to_string());
        for stat in TotalProcessStat::iter() {
            let mut snode = Node::new(newkey(pid, &mut key), stat.to_string());
            for r in process.runs.iter() {
                snode.add_child(Node::new(
                    newkey(pid, &mut key),
                    format!(
                        "{}: {}",
                        r.start_time.format("%H:%M:%S"),
                        r.total_stat_str(&stat)
                    ),
                ));
            }
            pstat.add_child(snode);
        }
        pnode.add_child(pstat);

        let threads = process.sorted_threads();
        if threads.len() > 1 {
            let mut threads_node = Node::new(
                format!("threads_{}", process.pid),
                format!("Threads: {}", threads.len()).to_string(),
            );
            for thread in threads.iter() {
                threads_node.add_child(Node::new(
                    format!("thread_{}_{}", process.pid, thread.pid),
                    format!("{} ({})", thread.comm, thread.pid).to_string(),
                ));
            }
            pnode.add_child(threads_node);
        }

        let mut pevents = Node::new(newkey(pid, &mut key), "Preempt Events".to_string());
        for r in process.runs.iter() {
            let mut run_pevents = Node::new(
                newkey(pid, &mut key),
                format!(
                    "Run: {}, events {}",
                    r.start_time.format("%H:%M:%S"),
                    r.preempt_events.len()
                )
                .to_string(),
            );
            for pevent in r.preempt_events.iter() {
                let mut pevent_node = Node::new(
                    newkey(pid, &mut key),
                    format!("{}: {}", pevent.comm, pevent.count).to_string(),
                );
                pevent_node.add_child(Node::new(
                    newkey(pid, &mut key),
                    format!("Pid: {}", pevent.preempt_pid).to_string(),
                ));
                pevent_node.add_child(Node::new(
                    newkey(pid, &mut key),
                    format!("Tgid: {}", pevent.preempt_tgid).to_string(),
                ));
                pevent_node.add_child(Node::new(
                    newkey(pid, &mut key),
                    format!("Cgid: {}", pevent.cgid).to_string(),
                ));
                pevent_node.add_child(Node::new(
                    newkey(pid, &mut key),
                    format!("Count: {}", pevent.count).to_string(),
                ));
                run_pevents.add_child(pevent_node);
            }
            if run_pevents.count() > 1 {
                pevents.add_child(run_pevents);
            }
        }
        if pevents.count() > 1 {
            pnode.add_child(pevents);
        }
    }

    fn processes_to_nodes(processes: &Vec<Process>) -> Node<String> {
        let mut node = Node::new("processes".to_string(), "Processes".to_string());
        for process in processes.iter() {
            node.add_child(Node::new(
                format!("process_{}", process.pid),
                format!("{} ({})", process.comm, process.pid).to_string(),
            ));
        }
        node
    }

    fn reload_tree(&mut self) {
        let current_node = match self.app.state(&Id::ProcessTree).ok().unwrap() {
            State::One(StateValue::String(node)) => Some(node),
            _ => None,
        };
        let title = format!("Processes: {}", self.process_vec.len()).to_string();
        let mut scroll = self.process_vec.len();
        scroll /= 4;
        self.app
            .umount(&Id::ProcessTree)
            .expect("Failed to unmount process tree");
        self.app
            .mount(
                Id::ProcessTree,
                Box::new(ProcessTree::new(
                    self.tree.clone(),
                    current_node,
                    title,
                    scroll,
                )),
                vec![],
            )
            .expect("Failed to mount process tree");
        self.app
            .active(&Id::ProcessTree)
            .expect("Failed to set focus to ProcessTree");
    }
}

impl Update<Msg> for Model {
    fn update(&mut self, msg: Option<Msg>) -> Option<Msg> {
        self.redraw = true;
        match msg.unwrap_or(Msg::None) {
            Msg::AppClose => {
                self.quit = true;
                None
            }
            Msg::OpenProcess(key) => {
                match key.split('_').collect::<Vec<&str>>().as_slice() {
                    ["process", pid] => {
                        let pid = pid.parse::<u32>().unwrap();
                        if let Some(node) = self.tree.root_mut().query_mut(&key) {
                            node.clear();
                            if let Some(process) = self.process_vec.iter().find(|p| p.pid == pid) {
                                Self::process_to_nodes(node, process);
                            }
                        }
                        self.reload_tree();
                    }
                    ["thread", pid, tid] => {
                        let pid = pid.parse::<u32>().unwrap();
                        let tid = tid.parse::<u32>().unwrap();
                        if let Some(node) = self.tree.root_mut().query_mut(&key) {
                            node.clear();
                            if let Some(thread) = self.process_vec.iter().find(|p| p.pid == pid) {
                                if let Some(thread) = thread.threads.get(&tid) {
                                    Self::process_to_nodes(node, thread);
                                }
                            }
                        }
                        self.reload_tree();
                    }
                    _ => {}
                }
                None
            }
            Msg::None => None,
        }
    }
}

#[derive(MockComponent)]
pub struct ProcessTree {
    component: TreeView<String>,
}

impl ProcessTree {
    pub fn new(
        tree: Tree<String>,
        inital_node: Option<String>,
        title: String,
        scroll: usize,
    ) -> Self {
        let focus = match inital_node {
            Some(node) if tree.root().query(&node).is_some() => node,
            _ => tree.root().id().to_string(),
        };
        ProcessTree {
            component: TreeView::default()
                .foreground(Color::Reset)
                .borders(
                    Borders::default()
                        .color(Color::LightYellow)
                        .modifiers(BorderType::Rounded),
                )
                .inactive(Style::default().fg(Color::Gray))
                .indent_size(3)
                .preserve_state(true)
                .scroll_step(scroll)
                .title(title, Alignment::Left)
                .highlighted_color(Color::LightYellow)
                .highlight_symbol("🦄")
                .with_tree(tree)
                .initial_node(focus),
        }
    }
}

impl Component<Msg, NoUserEvent> for ProcessTree {
    fn on(&mut self, ev: Event<NoUserEvent>) -> Option<Msg> {
        let result = match ev {
            Event::Keyboard(KeyEvent {
                code: Key::Left,
                modifiers: KeyModifiers::NONE,
            }) => self.perform(Cmd::Custom(TREE_CMD_CLOSE)),
            Event::Keyboard(KeyEvent {
                code: Key::Right,
                modifiers: KeyModifiers::NONE,
            }) => self.perform(Cmd::Custom(TREE_CMD_OPEN)),
            Event::Keyboard(KeyEvent {
                code: Key::PageDown,
                modifiers: KeyModifiers::NONE,
            }) => self.perform(Cmd::Scroll(Direction::Down)),
            Event::Keyboard(KeyEvent {
                code: Key::PageUp,
                modifiers: KeyModifiers::NONE,
            }) => self.perform(Cmd::Scroll(Direction::Up)),
            Event::Keyboard(KeyEvent {
                code: Key::Down,
                modifiers: KeyModifiers::NONE,
            }) => self.perform(Cmd::Move(Direction::Down)),
            Event::Keyboard(KeyEvent {
                code: Key::Up,
                modifiers: KeyModifiers::NONE,
            }) => self.perform(Cmd::Move(Direction::Up)),
            Event::Keyboard(KeyEvent {
                code: Key::Enter,
                modifiers: KeyModifiers::NONE,
            }) => self.perform(Cmd::Submit),
            _ => return None,
        };
        match result {
            CmdResult::Submit(State::One(StateValue::String(node))) => Some(Msg::OpenProcess(node)),
            _ => Some(Msg::None),
        }
    }
}

#[derive(Default, MockComponent)]
pub struct GlobalListener {
    component: Phantom,
}

impl Component<Msg, NoUserEvent> for GlobalListener {
    fn on(&mut self, ev: Event<NoUserEvent>) -> Option<Msg> {
        match ev {
            Event::Keyboard(KeyEvent {
                code: Key::Esc,
                modifiers: KeyModifiers::NONE,
            }) => Some(Msg::AppClose),
            _ => None,
        }
    }
}

pub fn launch_tui(processes: Vec<Process>) {
    let mut model = Model::new(processes);
    let _ = model.terminal.enter_alternate_screen();
    let _ = model.terminal.clear_screen();
    let _ = model.terminal.enable_raw_mode();
    let _ = model.terminal.disable_mouse_capture();

    while !model.quit {
        if let Ok(messages) = model.app.tick(PollStrategy::Once) {
            for msg in messages.into_iter() {
                let mut msg = Some(msg);
                while msg.is_some() {
                    msg = model.update(msg);
                }
            }
        }
        if model.redraw {
            model.view();
            model.redraw = false;
        }
    }

    let _ = model.terminal.leave_alternate_screen();
    let _ = model.terminal.disable_raw_mode();
    let _ = model.terminal.clear_screen();
}
