/*******************

Team members and IDs:
Taylor Martinez 5869579

Github link:
https://github.com/xxx/yyy

*******************/

package net.floodlightcontroller.myrouting;

import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.PriorityQueue;
import java.util.Queue;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.util.ArrayList;
import java.util.Set;
import java.util.TreeMap;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.topology.OrderedNodePair;

import org.openflow.util.HexString;
import org.openflow.util.U8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.deser.DataFormatReaders.Match;

public class MyRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected IDeviceService deviceProvider;
	protected ILinkDiscoveryService linkProvider;

	protected Map<Long, IOFSwitch> switches;
	protected Map<Link, LinkInfo> links;
	protected Collection<? extends IDevice> devices;

	protected static int uniqueFlow;
	protected ILinkDiscoveryService lds;
	protected IStaticFlowEntryPusherService flowPusher;
	protected boolean printedTopo = false;
	
	protected String old_ns;
	protected String old_nd;

	@Override
	public String getName() {
		return MyRouting.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN)
				&& (name.equals("devicemanager") || name.equals("topology")) || name
					.equals("forwarding"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ILinkDiscoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		linkProvider = context.getServiceImpl(ILinkDiscoveryService.class);
		flowPusher = context
				.getServiceImpl(IStaticFlowEntryPusherService.class);
		lds = context.getServiceImpl(ILinkDiscoveryService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		Map<Link, OrderedNodePair> edges = new TreeMap<>();
		Map<NodePortTuple, Link> switchPortLinks = new HashMap<>();
		Map<String, NodePortTuple> nodes = new HashMap<>();
		Map<Long, Integer> cost = new HashMap<>();
		Map<Long, Long> previousNode = new HashMap<>();
		ArrayList<NodePortTuple> path = new ArrayList<NodePortTuple>();
		List<Long> pathL = new ArrayList<>();
		
		switches = floodlightProvider.getAllSwitchMap();
		links = linkProvider.getLinks();
		
		String netsrc, netdst;
		
		// Print the topology if not yet.
		if (!printedTopo) {
			System.out.println("*** Print topology");
			// For each switch, print its neighbor switches.		
			for( IOFSwitch i : switches.values()) {
				System.out.print("switch " + i.getId() + " neighbors: ");
				for (Link j : links.keySet()) {
					if(j.getSrc() == i.getId()) {
						System.out.print(j.getDst() + " ");
					}
				}
				System.out.print("\n");
			}
				
			old_ns = "";
			old_nd = "";

			printedTopo = true;
		}

		// eth is the packet sent by a switch and received by floodlight.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		// We process only IP packets of type 0x0800. 		
		if (eth.getEtherType() != 0x0800) {
			return Command.CONTINUE;
		}
		else{
			// Parse the incoming packet.
			OFPacketIn pi = (OFPacketIn)msg;
			OFMatch match = new OFMatch();
		    match.loadFromPacket(pi.getPacketData(), pi.getInPort());
			
			// Obtain source and destination IPs.
			// ...
		    
		    netsrc = match.getNetworkSourceCIDR().substring(0, (match.getNetworkSourceCIDR().length() - 3));
		    netdst = match.getNetworkDestinationCIDR().substring(0, (match.getNetworkDestinationCIDR().length() - 3));
		    
		    if((netsrc.compareTo(old_ns) == 0) && (netdst.compareTo(old_nd) == 0)) {
		    	return Command.STOP;
		    }
		    
		    System.out.println("*** New flow packet");
		    
			System.out.println("srcIP: " + netsrc);
	        System.out.println("dstIP: " + netdst);
	        
	        old_ns = netsrc;
	        old_nd = netdst;

			// Calculate the path using Dijkstra's algorithm.
	        
	        for( IOFSwitch i : switches.values()) {
				for (Link j : links.keySet()) {
					if(j.getSrc() == i.getId()) {
						NodePortTuple tuple = new NodePortTuple(i.getId(), j.getSrcPort());
						nodes.put("S" + Long.toString(i.getId()), tuple);						
						switchPortLinks.put(tuple, j);
					}
				}
	        }
	        
	        Long sourceNode = Long.decode(netsrc.substring(netdst.length() - 1));
	        
	        Long destNode = Long.decode(netdst.substring(netdst.length() - 1));
			
//			1 Initialization:
//			2 N’ = {u}
			path.add(nodes.get(Long.toString(sourceNode)));
			pathL.add(sourceNode);
//			3 for all nodes v
			for(Entry<NodePortTuple, Link> i : switchPortLinks.entrySet()) {
				Link value = i.getValue();
//				4 if v is a neighbor of u
				if(value.getSrc() == sourceNode) {
//					5 then D(v) = c(u, v)
					if(!(value.getSrc() % 2 == 0) && !(value.getDst() % 2 == 0)) {
						cost.put(value.getDst(), 1);
					} else if ((value.getSrc() % 2 == 0) && (value.getDst() % 2 == 0)) {
						cost.put(value.getDst(), 100);
					} else {
						cost.put(value.getDst(), 10);
					}
					previousNode.put(value.getDst(), value.getSrc());
				} else {
	//				6 else D(v) = infinity
					if(!(cost.containsKey(value.getDst()))) {
						cost.put(value.getDst(), 1000000);
					}
				}
			}
			
			cost.put(sourceNode, 0);
			
			long minKey = 0;
			long min = 0;
			
			int count = 1;
			
//			8 Loop
//			15 until N’= N
			while(pathL.size() != switches.size()) {
//				9 find w not in N’ such that D(w) is a minimum
				for(Entry<NodePortTuple, Link> i : switchPortLinks.entrySet()) {
					if(previousNode.containsKey(i.getKey().getNodeId())) {
						if(!(pathL.contains(i.getKey().getNodeId()))) {
							if(count == 1) {
								minKey = i.getKey().getNodeId();
								min = cost.get(i.getKey().getNodeId());
								count++;
							}
							if(cost.get(i.getKey().getNodeId()) < min) {
								minKey = i.getKey().getNodeId();
								min = cost.get(i.getKey().getNodeId());
							}
						}
					}
				}
				
//				System.out.println("Path: " + pathL.toString());
//				System.out.println("Minkey: " + minKey);
//				System.out.println("MinCost: " + min);
				
//				10 add w to N’
				path.add(nodes.get(Long.toString(minKey)));
				pathL.add(minKey);
//				11 update D(v) for each neighbor v of w and not in N’:
				for(Entry<NodePortTuple, Link> i : switchPortLinks.entrySet()) {
					Link value = i.getValue();
//					12 D(v) = min(D(v), D(w)+ c(w, v) ) /* new cost to v is either old cost to v or known 
					// least path cost to w plus cost from w to v */
					if(value.getSrc() == minKey && !(pathL.contains(value.getDst()))) {
						if(!previousNode.containsKey(value.getDst())) {
							previousNode.put(value.getDst(), value.getSrc());
						}
						
						Long prevNode = previousNode.get(value.getDst());
						Long prevCost = (long) 0;
						
						while(prevNode !=  null) {
							prevCost += cost.get(prevNode);
							prevNode = previousNode.get(prevNode);
						}
						
						if(cost.containsKey(value.getDst()) && (cost.get(value.getDst()) == 1000000)) {
							if(!(value.getSrc() % 2 == 0) && !(value.getDst() % 2 == 0)) {
								cost.put(value.getDst(), prevCost.intValue() + 1);
							} else if ((value.getSrc() % 2 == 0) && (value.getDst() % 2 == 0)) {
								cost.put(value.getDst(), prevCost.intValue() + 100);
							} else {
								cost.put(value.getDst(), prevCost.intValue() + 10);
							}
						}
						
						
						if(!(value.getSrc() % 2 == 0) && !(value.getDst() % 2 == 0)) {
							cost.put(value.getDst(), Math.min(cost.get(value.getDst()), cost.get(value.getDst()) + 1));
						} else if ((value.getSrc() % 2 == 0) && (value.getDst() % 2 == 0)) {
							cost.put(value.getDst(), Math.min(cost.get(value.getDst()), cost.get(value.getDst()) + 100));
						} else {
							cost.put(value.getDst(), Math.min(cost.get(value.getDst()), cost.get(value.getDst()) + 10));
						}
					}
				}
				
//				System.out.println(cost.toString());
//				System.out.println("PN: " + previousNode.toString());
				
				count = 1;
				min = 0;
				minKey = 0;
			}
			
//			System.out.println("PathL: " + pathL.toString());
			
			String routeString = destNode.toString();
			Long prevNode = previousNode.get(destNode);
			Deque<Long> queue = new LinkedList<>();
			queue.add(destNode);
			
			while(prevNode != null) {
				queue.addFirst(prevNode); 
				routeString = prevNode + " " + routeString;
				prevNode = previousNode.get(prevNode);
			}
			
			Deque<Long> reverseQ = new LinkedList<>(queue);
			
//			System.out.println("Queue: " + queue);	
			
			Long srcNode = (long) 0;
			Long dstNode = (long) 0;
			
			srcNode = queue.pollFirst();
			
			path.removeAll(path);
			
			while(!queue.isEmpty()) {
				dstNode = queue.pollFirst();
//				System.out.println("Queue: " + queue);
//				System.out.println("Src: " + srcNode.toString() + " Dest: " + dstNode.toString()); 
				for(Entry<NodePortTuple, Link> i : switchPortLinks.entrySet()) {
					Link value = i.getValue();
					if((value.getSrc() == srcNode) && (value.getDst() == dstNode)) {
						path.add(new NodePortTuple(value.getSrc(), value.getSrcPort()));
						path.add(new NodePortTuple(value.getDst(), value.getDstPort()));
					}
				}
				srcNode = dstNode;
			}
			
//			srcNode = reverseQ.pollLast();
//			
//			while(!reverseQ.isEmpty()) {
//				dstNode = reverseQ.pollLast();
////				System.out.println("Queue: " + queue);
////				System.out.println("Src: " + srcNode.toString() + " Dest: " + dstNode.toString()); 
//				for(Entry<NodePortTuple, Link> i : switchPortLinks.entrySet()) {
//					Link value = i.getValue();
//					if((value.getSrc() == srcNode) && (value.getDst() == dstNode)) {
//						path.add(new NodePortTuple(value.getSrc(), value.getSrcPort()));
//						path.add(new NodePortTuple(value.getDst(), value.getDstPort()));
//					}
//				}
//				srcNode = dstNode;
//			}
	        
//			Route route = null;
			Route route = new Route(new RouteId(sourceNode, destNode), path);
			
//			if(path != null) {
//				System.out.println("Path: " + path.toString());
//			}
			
			System.out.println("route: " + routeString);

			// Write the path into the flow tables of the switches on the path.
			if (route != null) {
				installRoute(route.getPath(), match);
			}
			
			return Command.STOP;
		}
	}

	// Install routing rules on switches. 
	private void installRoute(List<NodePortTuple> path, OFMatch match) {

		OFMatch m = new OFMatch();

		m.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkSource(match.getNetworkSource())
				.setNetworkDestination(match.getNetworkDestination());

		for (int i = 0; i <= path.size() - 1; i += 2) {
			short inport = path.get(i).getPortId();
			m.setInputPort(inport);
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(path.get(i + 1)
					.getPortId());
			actions.add(outport);

			OFFlowMod mod = (OFFlowMod) floodlightProvider
					.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			mod.setCommand(OFFlowMod.OFPFC_ADD)
					.setIdleTimeout((short) 0)
					.setHardTimeout((short) 0)
					.setMatch(m)
					.setPriority((short) 105)
					.setActions(actions)
					.setLength(
							(short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow" + uniqueFlow, mod,
					HexString.toHexString(path.get(i).getNodeId()));
			uniqueFlow++;
		}
	}
}
