// initialize global variables.
var edges;
var nodes;
var allNodes;
var allEdges;
var nodeColors;
var originalNodes;
var network;
var container;
var options, data;
var filter = {
    item: '',
    property: '',
    value: []
};

// view node information
var info = new Vue({
    el: "#network_info",
    delimiters:['{[', ']}'],
    data: {
            content: {}
    }
})

// This method is responsible for drawing the graph, returns the drawn network
function drawGraph(in_nodes, in_edges) {
    var container = document.getElementById('mynetwork');
    // parsing and collecting nodes and edges from the python
    
    nodes = new vis.DataSet(in_nodes);
    edges = new vis.DataSet(in_edges);
    nodeColors = {};
    allNodes = nodes.get({
        returnType: "Object"
    });
    for (nodeId in allNodes) {
        nodeColors[nodeId] = allNodes[nodeId].color;
    }
    allEdges = edges.get({
        returnType: "Object"
    });
    // adding nodes and edges to the graph
    data = {
        nodes: nodes,
        edges: edges
    };

    var options = {
        "configure": {
            "enabled": false
        },
        "edges": {
            "color": {
                "inherit": true
            },
            "smooth": {
                "enabled": true,
                "type": "dynamic"
            }
        },
        "interaction": {
            "dragNodes": true,
            "hideEdgesOnDrag": false,
            "hideNodesOnDrag": false
        },
        "physics": {
            "enabled": true,
            "stabilization": {
                "enabled": true,
                "fit": true,
                "iterations": 1000,
                "onlyDynamicEdges": false,
                "updateInterval": 50
            }
        }
    };
    network = new vis.Network(container, data, options);
    return network;
}

function addNode(in_node) {
    nodes.update(in_node);
}