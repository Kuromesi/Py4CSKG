

modeling = new Vue({
    el: "#modeling",
    delimiters: ['{[', ']}'],
    data: {
        ontology: {
            component: {
                name: "Name",
                description: "Description"
            },
            software: {
                product: "Product",
                version: "Version"
            },
            hardware: {
                product: "Product",
                version: "Version"
            },
            firmware: {
                product: "Product",
                version: "Version"
            },
            os: {
                product: "Product",
                version: "Version"
            },
            entry: {
                name: "",
                access: "Local, network"
            },
            defender: {
                name: "",
                description: ""
            }
        },
        key: "",
        type: 0,
        name: "",
        description: "",
        product: "",
        version: "",
        node: {},
        cur_component: {
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
        cur_component: {},
        source: {},
        dest: {},
        protocol: "",
        files: [],
        cur_project: "",
        clicked: {},
        recommendations: [],
        if_recommend: true
    },
    methods: {
        select_node(type) {
            if (this.cur_component.name)
                node_name = this.cur_component.name;
            else
                node_name = this.cur_component.product;
            if (type == "source") {
                Object.assign(this.source, this.clicked);
                this.cur_edge.source = node_name;
            } else {
                Object.assign(this.dest, this.clicked);
                this.cur_edge.dest = node_name;
            }
        },
        add_node() {
            component_attributes = {
                component: {
                    color: "#00ff00",
                    size: 13.75
                },
                software: {
                    color: "#99dfff",
                    size: 10
                },
                hardware: {
                    color: "#ffff66",
                    size: 10
                },
                firmware: {
                    color: "#996633",
                    size: 10
                },
                os: {
                    color: "#9966ff",
                    size: 10
                },
                entry: {
                    color: "#669999",
                    size: 10
                },
                defender: {
                    color: "#0066ff",
                    size: 13.75
                }
            }
            var node = {}
            for (k in this.cur_component) {
                node[k] = this.cur_component[k];
            }
            node.color = component_attributes[this.cur_component.type].color;
            node.size = component_attributes[this.cur_component.type].size;
            node.shape = "dot";
            if (this.cur_component.name) {
                node.title = this.cur_component.name;
                node.label = this.cur_component.name;
            } else {
                node.title = this.cur_component.product;
                node.label = this.cur_component.product;
            }
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
                for (k in this.cur_component) {
                    this.clicked[k] = this.cur_component[k];
                }
                if (this.cur_component.name) {
                    this.clicked.title = this.cur_component.name;
                    this.clicked.label = this.cur_component.name;
                } else {
                    this.clicked.title = this.cur_component.product;
                    this.clicked.label = this.cur_component.product;
                }
            } else {
                alert("Network not initialized!")
            }
            addNode(this.clicked)
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
            } else {
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
            }
        },
        list_files() {
            var url = "/model/list";
            axios({
                method: 'post',
                url: url
            }).then(function (res) {
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
                modeling.cur_project = file;
                var graph = res.data;
                network = drawGraph(graph.nodes, graph.edges);
                network.on('click', network_click);
            })
        },
        fill_product(recommendation) {
            this.cur_component.product = recommendation;
            this.if_recommend = false;
            this.recommendations = [];
        },
        component_click(type) {
            this.cur_component = {};
            this.cur_component.type = type;
            for (key in this.ontology[type])
                this.cur_component[key] = this.ontology[type][key];
        },
        add_attribute() {
            if (this.cur_component[this.key] != undefined) {
                this.$delete(this.cur_component, this.key);
            } else {
                this.$set(this.cur_component, this.key, "");
            }
        }
    },
    watch: {
        'cur_component.product': {
            handler (newVal, oldVal) {
                if (!this.if_recommend) {
                    this.if_recommend = true;
                } else if (this.cur_component.product) {
                    var url = "/model/keyword"
                    axios({
                        method: 'post',
                        url: url,
                        data: { query: newVal }
                    }).then(function (res) {
                        modeling.recommendations = res.data;
                    })
                }
                
            }
        }
    }
});

// modeling.$watch('cur_component.product', function (after, berfore) {
//     if (!this.if_recommend) {
//         this.if_recommend = true;
//     } else if (this.cur_component.product) {
//         var url = "/model/keyword"
//         axios({
//             method: 'post',
//             url: url,
//             data: { query: after }
//         }).then(function (res) {
//             modeling.recommendations = res.data;
//         })
//     }
// });

var attributes = ['label', 'id', 'color', 'shape', 'size', 'title'];

function network_click(params) {
    if (params.nodes.length != 0) {
        var nodeID = params.nodes[0];
        if (nodeID) {
            clickedNode = nodes.get(nodeID);
        }
        info.content = clickedNode;
        modeling.clicked = clickedNode;
        modeling.type = clickedNode.type;
        modeling.cur_component = {};
        for (key in clickedNode) {
            if (attributes.indexOf(key) > -1)
                continue;
            modeling.cur_component[key] = clickedNode[key];
        }

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