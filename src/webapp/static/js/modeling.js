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
        id: 1
    },
    methods: {
        add_node() {
            switch (this.type) {
                case 1:
                    type = "Component";
                    break;
                case 2:
                    type = "Software";
                    break;
                case 3:
                    type = "Hardware";
                    break;
                case 4:
                    type = "Firmware";
                    break;
                case 5:
                    type = "Entry";
                    break;
                case 6:
                    type = "OS";
                    break;
            }
            this.node = [{
                "type": type,
                "name": this.name,
                "description": this.description,
                "product": this.product,
                "version": this.version,
                "color": "#00ff00",
                "id": this.id,
                "label": this.name,
                "shape": "dot",
                "size": 13.75
            }];
            if (network) {
                addNode(this.node);
            } else {
                network = drawGraph(this.node, [{}]);
                network.on('click', function (params) {
                    if (params.nodes.length != 0) {
                        var nodeID = params.nodes[0];
                        if (nodeID) {
                            clickedNode = nodes.get(nodeID);
                        }
                        // content = clickedNode.id
                        info.content = clickedNode
                    }
                });
            }
            this.id++;
        }
    }
})