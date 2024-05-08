// This method is responsible for drawing the graph, returns the drawn network
function drawGraph(nodes, edges) {
    // initialize global variables.
    var network;
    var container;
    var options, data;
    var container = document.getElementById('mynetwork');
    // parsing and collecting nodes and edges from the python
    // adding nodes and edges to the graph
    data = {
        nodes: nodes,
        edges: edges
    };

    var options = {
        "configure": {
            "enabled": false,
            "filter": [
                "physics",
                "nodes",
                "edges"
            ]
        },
        "edges": {
            "color": {
                "inherit": true
            },
            "smooth": {
                "enabled": false,
                "type": "continuous"
            }
        },
        "interaction": {
            "dragNodes": true,
            "hideEdgesOnDrag": false,
            "hideNodesOnDrag": false
        },
        "physics": {
            "enabled": true,
            "hierarchicalRepulsion": {
                "centralGravity": 0.0,
                "damping": 0.09,
                "nodeDistance": 120,
                "springConstant": 0.01,
                "springLength": 100
            },
            "solver": "hierarchicalRepulsion",
            "stabilization": {
                "enabled": true,
                "fit": true,
                "iterations": 1000,
                "onlyDynamicEdges": false,
                "updateInterval": 50
            }
        }
    };

    // if this network requires displaying the configure window,
    // put it in its div
    // options.configure["container"] = document.getElementById("config");
    network = new vis.Network(container, data, options);
    return network;
}