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
                access: "Network, adjacent, local, physical"
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
            this.product = recommendation;
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
        product: {
            handler(newVal, oldVal) {
                if (!this.if_recommend) {
                    this.if_recommend = true;
                } else if (this.product) {
                    this.cur_component.product = this.product;
                    var url = "/model/keyword";
                    axios({
                        method: 'post',
                        url: url,
                        data: {
                            query: newVal
                        }
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
        node_control.clicked_node = clickedNode;
        // modeling.type = clickedNode.type;
        // modeling.cur_component = {};
        for (key in clickedNode) {
            if (attributes.indexOf(key) > -1)
                continue;
            if (key == "component") {
                node_control.cur_node[key] = JSON.parse(JSON.stringify(clickedNode[key]))
            } else {
                node_control.cur_node[key] = clickedNode[key];
            }
        }
        // modeling.product = clickedNode.product;
    } else if (params.edges.length != 0) {
        var edgeID = params.edges[0];
        if (edgeID) {
            clickedEdge = edges.get(edgeID);
        }
        info.content = clickedEdge;
        // modeling.clicked = clickedEdge;
        edge_control.selected_edge.source = JSON.parse(JSON.stringify(nodes.get(clickedEdge.from)))
        edge_control.selected_edge.dest = JSON.parse(JSON.stringify(nodes.get(clickedEdge.to)))
        // edge_control.selected_edge.protocol = clickedEdge.protocol;
    }
}

node_control = new Vue({
    el: "#node-control",
    delimiters: ['{[', ']}'],
    data: {
        cur_node: {
            name: "",
            group: "",
            entry: {},
            component: {
                os: {},
                software: {},
                firmware: {},
                hardware: {},
                cve: {}
            },
            description: ""
        },
        clicked_node: {},
        selected_component: {},
        component_type: "os",
        selected_product: {
            product: "",
            version: "",
            access: "NETWORK",
            privilege: "user"
        },
        selected_cve: {
            cve: "",
            description: ""
        },
        selected_entry: {
            entry: "",
            description: ""
        },
        recommended_products: [],
        if_recommend: false
    },
    methods: {
        add_node() {
            node = {}
            for (k in this.cur_node) {
                if (k == "component") {
                    node[k] = JSON.parse(JSON.stringify(this.cur_node[k]))
                } else {
                    node[k] = this.cur_node[k]
                }
            }
            node.title = this.cur_node.name;
            node.label = this.cur_node.name;
            if (network) {
                addNode(node);
            } else {
                network = drawGraph([node], [{}])
                network.on('click', network_click)
            }
            this.cur_node = {
                name: "",
                group: "",
                entry: {},
                component: {
                    os: {},
                    software: {},
                    firmware: {},
                    hardware: {},
                    cve: {}
                },
                description: ""
            }
        },
        delete_node() {
            network.deleteSelected()
        },
        modify_node() {
            if (network) {
                for (k in this.cur_node) {
                    if (k == "component") {
                        this.clicked_node[k] = JSON.parse(JSON.stringify(this.cur_node[k]))
                    }
                    this.clicked_node[k] = this.cur_node[k];
                }
                this.clicked_node.title = this.cur_node.name;
                this.clicked_node.label = this.cur_node.name;
            } else {
                alert("Network not initialized!")
            }
            addNode(this.clicked_node)
        },
        select_component(component) {
            switch (component) {
                case 'os':
                    console.log("os selected")
                    this.$set(this.selected_component, this.cur_node["component"]["os"])
                    this.component_type = "os"
                    break
                case 'software':
                    console.log("software selected")
                    this.$set(this.selected_component, this.cur_node["component"]["software"])
                    this.component_type = "software"
                    break
                case 'firmware':
                    console.log("firmware selected")
                    this.$set(this.selected_component, this.cur_node["component"]["firmware"])
                    this.component_type = "firmware"
                    break
                case 'hardware':
                    console.log("hardware selected")
                    this.$set(this.selected_component, this.cur_node["component"]["hardware"])
                    this.component_type = "hardware"
                    break
                case 'cve':
                    console.log("cve selected")
                    this.$set(this.selected_component, this.cur_node["component"]["cve"])
                    this.component_type = "cve"
                    break
                case 'entry':
                    console.log("entry selected")
                    this.$set(this.selected_component, this.cur_node["entry"])
                    this.component_type = "entry"
                    break
            }
        },
        add_component() {
            if (this.component_type == "entry") {
                this.$set(this.cur_node["entry"], this.selected_entry["entry"], JSON.parse(JSON.stringify(this.selected_entry)))
            } else if (this.component_type == "cve") {
                this.$set(this.cur_node["component"][this.component_type], this.selected_cve["cve"], JSON.parse(JSON.stringify(this.selected_cve)))
                this.selected_cve = {
                    cve: "",
                    description: ""
                }
            } else {
                this.$set(this.cur_node["component"][this.component_type], this.selected_product["product"], JSON.parse(JSON.stringify(this.selected_product)))
                this.selected_product = {
                    product: "",
                    version: "",
                    access: "NETWORK",
                    privilege: "user"
                }
            }
        },
        delete_component() {
            if (this.component_type == "entry") {
                Vue.delete(this.cur_node["entry"], this.selected_entry["entry"])
            } else if (this.component_type == "cve") {
                Vue.delete(this.cur_node["component"][this.component_type], this.selected_cve["cve"])
            } else {
                this.$set(this.cur_node["component"][this.component_type], this.selected_product["product"], JSON.parse(JSON.stringify(this.selected_product)))
                this.selected_product = {
                    product: "",
                    version: "",
                    access: "NETWORK",
                    privilege: "user"
                }
            }
        },
        check_component_details(name) {
            if (this.component_type == "entry") {
                this.selected_entry = JSON.parse(JSON.stringify(this.cur_node["entry"][name]))
            } else if (this.component_type == "cve") {
                this.selected_cve = JSON.parse(JSON.stringify(this.cur_node["component"][this.component_type][name]))
            } else {
                this.selected_product = JSON.parse(JSON.stringify(this.cur_node["component"][this.component_type][name]))
            }
        },
        add_product() {
            this.$set(this.cur_node["component"][this.component_type], this.selected_product["product"], JSON.parse(JSON.stringify(this.selected_product)))
            this.selected_product = {
                product: "",
                version: "",
                access: "network",
                privilege: "user"
            }
        },
        delete_product() {
            Vue.delete(this.cur_node["component"][this.component_type], this.selected_product["product"])
        },
        add_cve() {
            if (!Object.keys(this.cur_node["component"]).includes(this.component_type)) {
                this.cur_node["component"][this.component_type] = {}
            }
            this.$set(this.cur_node["component"][this.component_type], this.selected_cve["cve"], JSON.parse(JSON.stringify(this.selected_cve)))
            this.selected_cve = {
                cve: "",
                description: ""
            }
        },
        delete_cve() {
            Vue.delete(this.cur_node["component"][this.component_type], this.selected_cve["cve"])
        },
        select_cve(cve) {
            this.selected_cve = JSON.parse(JSON.stringify(this.cur_node["component"][this.component_type][cve]))
        },
        set_product_attributes(key, val) {
            this.$set(this.selected_product, key, val)
        },
        select_product(product) {
            this.selected_product = JSON.parse(JSON.stringify(this.cur_node["component"][this.component_type][product]))
        },
        product_on_blur() {
            this.if_recommend = false
        },
        product_on_focus() {
            this.if_recommend = true
        },
        debounce(func, delay = 1000, immediate = false) {
            let timer = null
            return function() {
                if (timer) {
                    clearTimeout(timer)
                }
                if (immediate && !timer) {
                    func.apply(this, arguments)
                }
                timer = setTimeout(() => {
                    func.apply(this, arguments)
                }, delay)
            }
        },
        fill_product(product) {
            this.$set(this.selected_product, "product", product)
            this.recommended_products = []
        }
    },
    mounted() {
        this.debounce_recommendation = this.debounce(function(newVal, oldVal) {
            if (node_control.if_recommend && newVal != oldVal) {
                var url = "/model/keyword";
                axios({
                    method: 'post',
                    url: url,
                    data: {
                        query: newVal
                    }
                }).then(function (res) {
                    console.log(`received data: [${res.data}]`)
                    node_control.recommended_products = res.data;
                })
            }
        }, delay=200)
    },
    watch: {
        'selected_product.product': {
            handler(newVal, oldVal) {
                this.debounce_recommendation(newVal, oldVal)
            }
        }
    }
})

edge_control = new Vue({
    el: "#edge-control",
    delimiters: ['{[', ']}'],
    data: {
        selected_edge: {
            src: {},
            dst: {}
        },
        edge_type: "undirected"
    },
    methods: {
        select_node(type) {
            if (type == "src") {
                this.$set(this.selected_edge, "src", JSON.parse(JSON.stringify(node_control.clicked_node)))
            } else {
                this.$set(this.selected_edge, "dst", JSON.parse(JSON.stringify(node_control.clicked_node)))
            }
        },
        delete_edge() {
            network.deleteSelected();
        },
        add_edge() {
            if (this.selected_edge.src.name && this.selected_edge.dst.name) {
                console.log("adding edge " + this.selected_edge.src.id + " -> " + this.selected_edge.dst.id)
                addEdge({
                    from: this.selected_edge.src.id,
                    to: this.selected_edge.dst.id,
                    src: this.selected_edge.src.name,
                    dst: this.selected_edge.dst.name,
                    edge_type: this.edge_type
                    // protocol: this.cur_edge.protocol
                });
            } else {
                alert("Must select 2 nodes to create an edge!")
            }
        },
        set_edge_type(val) {
            this.edge_type = val
        }
    }
})

project_control = new Vue({
    el: "#project-control",
    delimiters: ['{[', ']}'],
    data: {
        files: [],
        cur_project: "",
    },
    methods: {
        save_graph() {
            var data = {
                nodes: nodes.get(),
                edges: edges.get()
            };
            var url = "/model/submit";
            if (!this.cur_project) {
                alert("Please input project name!")
            } else {
                axios({
                    method: 'post',
                    url: url,
                    data: {
                        graph: data,
                        path: project_control.cur_project
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
                project_control.files = res.data;
            })
        },
        load_project(file) {
            var url = "/model/load"
            axios({
                method: 'post',
                url: url,
                data: file
            }).then(function (res) {
                project_control.cur_project = file;
                var graph = res.data;
                network = drawGraph(graph.nodes, graph.edges);
                network.on('click', network_click);
            })
        },
        new_graph() {
            network = drawGraph([], [{}])
        }
    }
})