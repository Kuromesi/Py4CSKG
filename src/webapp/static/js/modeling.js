

modeling = new Vue({
    el: "#modeling",
    delimiters: ['{[', ']}'],
    data: {
        type: 0,
        name: "",
        description: "",
        product: "",
        version: "",
        node: {},
        cur_node: {
            name: "",
            product: "",
            version: "",
            description: ""
        },
        cur_edge: {
            source: "",
            dest: "",
            protocol: ""
        },
        source: {},
        dest: {},
        protocol: "",
        files: [],
        cur_project: "",
        clicked: {}
    },
    methods: {
        select_node(type) {
            if (type == "source") {
                Object.assign(this.source, this.cur_node);
                this.cur_edge.source = this.cur_node.name
            } else {
                Object.assign(this.dest, this.cur_node);
                this.cur_edge.dest = this.cur_node.name
            }
        },
        add_node() {
            switch (this.type) {
                case 1:
                    type = "Component";
                    color = "#00ff00"
                    size = 13.75;
                    break;
                case 2:
                    type = "Software";
                    color = "#99dfff"
                    size = 10;
                    break;
                case 3:
                    type = "Hardware";
                    color = "#99dfff"
                    size = 10;
                    break;
                case 4:
                    type = "Firmware";
                    color = "#99dfff"
                    size = 10;
                    break;
                case 5:
                    type = "Entry";
                    color = "#99dfff"
                    size = 10;
                    break;
                case 6:
                    type = "OS";
                    color = "#99dfff"
                    size = 10;
                    break;
            }
            var node = {
                name: this.cur_node.name,
                description: this.cur_node.description,
                product: this.cur_node.product,
                version: this.cur_node.version,
                color: color,
                shape: "dot",
                size: size,
                label: this.cur_node.name,
                title: this.cur_node.name
            }

            // this.node = [{
            //     "type": type,
            //     "name": this.name,
            //     "description": this.description,
            //     "product": this.product,
            //     "version": this.version,
            //     "color": "#00ff00",
            //     "id": this.id,
            //     "label": this.name,
            //     "shape": "dot",
            //     "size": 13.75
            // }];
            if (network) {
                addNode(node);
            } else {
                network = drawGraph([node], [{}]);
                network.on('click', network_click);
            }
        },
        delete_node() {
            network.deleteSelected();
        },
        modify_node() {
            if (network) {
                this.clicked.name = this.cur_node.name;
                this.clicked.description = this.cur_node.description;
                this.clicked.version = this.cur_node.version;
                this.clicked.product = this.cur_node.product;
            } else {
                alert("Network not initialized!")
            }
        },
        modify_edge() {
            if (network) {
                this.clicked.protocol = this.cur_edge.protocol;
            } else {
                alert("Network not initialized!")
            }
        },
        add_edge() {
            if (this.source && this.dest) {
                addEdge({
                    from: this.source['id'],
                    to: this.dest['id'],
                    protocol: this.cur_edge.protocol
                });
                // edges.update([{
                //     from: this.source['id'],
                //     to: this.dest['id'],
                //     protocol: this.cur_edge.protocol
                // }
                // ])
            } else {
                alert("Must select 2 nodes to create an edge!");
            }
        },
        save_graph() {
            var data = {
                nodes: nodes.get(),
                edges: edges.get()
            };
            var url = "/model/submit";
            if (!modeling.cur_project) {
                alert("Please input project name!")
            }
            axios({
                method: 'post',
                url: url,
                data: {
                    graph: data,
                    path: modeling.cur_project
                }
            }).then(function (res) {
                alert(res.data);
            })
        },
        list_files() {
            var url = "/model/list";
            axios({
                method: 'post',
                url: url
            }).then(function (res) {
                console.log(res.data);
                modeling.files = res.data;
            })
        },
        load_project(file) {
            var url = "/model/load"
            axios({
                method: 'post',
                url: url,
                data: file
            }).then(function (res) {
                console.log(res.data);
                modeling.cur_project = file;
                var graph = res.data;
                network = drawGraph(graph.nodes, graph.edges);
                network.on('click', network_click);
            })
        }
    }
})

function network_click(params) {
    if (params.nodes.length != 0) {
                        var nodeID = params.nodes[0];
                        if (nodeID) {
                            clickedNode = nodes.get(nodeID);
                        }
                        info.content = clickedNode;
                        modeling.clicked = clickedNode;
                        Object.assign(modeling.cur_node, clickedNode);
                    } else if (params.edges.length != 0) {
                        var edgeID = params.edges[0];
                        if (edgeID) {
                            clickedEdge = edges.get(edgeID);
                        }
                        info.content = clickedEdge;
                        modeling.clicked = clickedEdge;
                        modeling.cur_edge.source = nodes.get(clickedEdge.from).name;
                        modeling.cur_edge.dest = nodes.get(clickedEdge.to).name;
                        modeling.cur_edge.protocol = clickedEdge.protocol;
                    }
}