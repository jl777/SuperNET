use atomicdex_gossipsub::{Gossipsub, GossipsubEvent, GossipsubMessage, Topic, TopicHash};
use futures::{channel::mpsc::UnboundedSender, lock::Mutex, Future, SinkExt};
use libp2p::{swarm::NetworkBehaviourEventProcess, NetworkBehaviour};
use std::{collections::HashMap, sync::Arc};

pub type MessageObserver = Vec<UnboundedSender<Arc<GossipsubMessage>>>;

/// AtomicDEX libp2p Network behaviour implementation
#[derive(NetworkBehaviour)]
pub struct AtomicDexBehavior {
    #[behaviour(ignore)]
    is_relayer: bool,
    #[behaviour(ignore)]
    message_observers: Arc<Mutex<HashMap<TopicHash, MessageObserver>>>,
    #[behaviour(ignore)]
    spawn_fn: fn(Box<dyn Future<Output = ()>>) -> (),
    gossipsub: Gossipsub,
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for AtomicDexBehavior {
    fn inject_event(&mut self, event: GossipsubEvent) {
        let observers = Arc::clone(&self.message_observers);
        println!("{:?}", self.is_relayer);
        match event {
            GossipsubEvent::Message(.., message) => {
                let message = Arc::new(message);
                (self.spawn_fn)(Box::new(async move {
                    let mut observers = observers.lock().await;
                    for topic in &message.topics {
                        if let Some(topic_observers) = observers.get_mut(topic) {
                            for observer in topic_observers {
                                if let Err(e) = observer.send(Arc::clone(&message)).await {
                                    println!("{}", e);
                                }
                            }
                        }
                    }
                }))
            },
            GossipsubEvent::Subscribed { peer_id: _, topic } => {
                if self.is_relayer {
                    let topic = Topic::new(topic.into_string());
                    self.gossipsub.subscribe(topic);
                }
            },
            _ => println!("{:?}", event),
        }
    }
}

#[test]
fn test_will_compile() {}
