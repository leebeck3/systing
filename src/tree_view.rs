use std::time::Duration;
use strum::IntoEnumIterator;
use tui_realm_stdlib::Phantom;
use tui_realm_treeview::{Node, Tree, TreeView, TREE_CMD_CLOSE, TREE_CMD_OPEN};
use tuirealm::terminal::CrosstermTerminalAdapter;
use tuirealm::{
    application::PollStrategy,
    command::{Cmd, Direction},
    event::{Event, Key, KeyEvent, KeyModifiers},
    props::{Alignment, BorderType, Borders, Color, Style},
    terminal::TerminalBridge,
    Application, Component, EventListenerCfg, MockComponent, NoUserEvent, Sub, SubClause,
    SubEventClause, Update,
};

use crate::process::{Process, ProcessStat};

#[derive(Debug, PartialEq)]
pub enum Msg {
    AppClose,
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
    redraw: bool,
    quit: bool,
    terminal: TerminalBridge<CrosstermTerminalAdapter>,
}

fn newkey(key: &mut u64) -> String {
    let k = *key;
    *key += 1;
    k.to_string()
}

impl Model {
    fn new(processes: &Vec<Process>) -> Self {
        let mut app = Application::init(
            EventListenerCfg::default().crossterm_input_listener(Duration::from_millis(10), 10),
        );
        app.mount(
            Id::ProcessTree,
            Box::new(ProcessTree::new(
                Tree::new(Self::processes_to_nodes(processes)),
                None,
            )),
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

    fn processes_to_nodes(processes: &Vec<Process>) -> Node<String> {
        let mut key: u64 = 0;
        let mut node = Node::new(newkey(&mut key), "processes".to_string());
        for p in processes.iter() {
            let mut pnode = Node::new(newkey(&mut key), p.comm.clone());
            pnode.add_child(Node::new(
                newkey(&mut key),
                format!("Pid: {}", p.pid).to_string(),
            ));
            pnode.add_child(Node::new(
                newkey(&mut key),
                format!("Cgroup ID: {}", p.stat.cgid).to_string(),
            ));
            for stat in ProcessStat::iter() {
                pnode.add_child(Node::new(newkey(&mut key), p.stat_str(stat)));
            }
            let mut threads_node = Node::new(
                newkey(&mut key),
                format!("Threads: {}", p.threads.len()).to_string(),
            );
            for thread in p.threads.iter() {
                let mut tnode = Node::new(newkey(&mut key), thread.comm.clone());
                tnode.add_child(Node::new(
                    newkey(&mut key),
                    format!("Pid: {}", thread.pid).to_string(),
                ));
                tnode.add_child(Node::new(
                    newkey(&mut key),
                    format!("Cgroup ID: {}", thread.stat.cgid).to_string(),
                ));
                for stat in ProcessStat::iter() {
                    tnode.add_child(Node::new(newkey(&mut key), thread.stat_str(stat)));
                }
                if thread.preempt_events.len() > 0 {
                    let mut pevents = Node::new(
                        newkey(&mut key),
                        format!("Preempt Events: {}", thread.preempt_events.len()).to_string(),
                    );
                    for pevent in thread.preempt_events.iter() {
                        let mut pevent_node = Node::new(
                            newkey(&mut key),
                            format!("{}: {}", pevent.comm, pevent.count).to_string(),
                        );
                        pevent_node.add_child(Node::new(
                            newkey(&mut key),
                            format!("Pid: {}", pevent.preempt_pid).to_string(),
                        ));
                        pevent_node.add_child(Node::new(
                            newkey(&mut key),
                            format!("Tgid: {}", pevent.preempt_tgid).to_string(),
                        ));
                        pevent_node.add_child(Node::new(
                            newkey(&mut key),
                            format!("Cgroup ID: {}", pevent.cgid).to_string(),
                        ));
                        pevent_node.add_child(Node::new(
                            newkey(&mut key),
                            format!("Count: {}", pevent.count).to_string(),
                        ));
                        pevents.add_child(pevent_node);
                    }
                    tnode.add_child(pevents);
                }
                threads_node.add_child(tnode);
            }
            if threads_node.count() > 1 {
                pnode.add_child(threads_node);
            }

            let mut pevents = Node::new(
                newkey(&mut key),
                format!("Preempt Events: {}", p.preempt_events.len()).to_string(),
            );
            for pevent in p.preempt_events.iter() {
                let mut pevent_node = Node::new(
                    newkey(&mut key),
                    format!("{}: {}", pevent.comm, pevent.count).to_string(),
                );
                pevent_node.add_child(Node::new(
                    newkey(&mut key),
                    format!("Pid: {}", pevent.preempt_pid).to_string(),
                ));
                pevent_node.add_child(Node::new(
                    newkey(&mut key),
                    format!("Tgid: {}", pevent.preempt_tgid).to_string(),
                ));
                pevent_node.add_child(Node::new(
                    newkey(&mut key),
                    format!("Cgid: {}", pevent.cgid).to_string(),
                ));
                pevent_node.add_child(Node::new(
                    newkey(&mut key),
                    format!("Count: {}", pevent.count).to_string(),
                ));
                pevents.add_child(pevent_node);
            }
            if pevents.count() > 1 {
                pnode.add_child(pevents);
            }

            node.add_child(pnode);
        }
        node
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
            Msg::None => None,
        }
    }
}

#[derive(MockComponent)]
pub struct ProcessTree {
    component: TreeView<String>,
}

impl ProcessTree {
    pub fn new(tree: Tree<String>, focus: Option<String>) -> Self {
        let focus = match focus {
            Some(id) if tree.root().query(&id).is_some() => id,
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
                .scroll_step(6)
                .title("Processes", Alignment::Left)
                .highlighted_color(Color::LightYellow)
                .highlight_symbol("🦄")
                .with_tree(tree)
                .initial_node(focus),
        }
    }
}

impl Component<Msg, NoUserEvent> for ProcessTree {
    fn on(&mut self, ev: Event<NoUserEvent>) -> Option<Msg> {
        match ev {
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
        Some(Msg::None)
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
    let mut model = Model::new(&processes);
    let _ = model.terminal.enter_alternate_screen();
    let _ = model.terminal.clear_screen();
    let _ = model.terminal.enable_raw_mode();

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
