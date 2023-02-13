submit = new Vue({
    el: "#app",
    methods: {
        send() {
            var cve = document.getElementById("inp").value;
            var role = {
                "cve": cve
            };
            var url = "/predict/submit";
            axios({
                method: 'post',
                url: '/predict/submit',
                data: role
            }).then(function (res) {
                console.log(res.data);
                var in_nodes = res.data.nodes;
                var in_edges = res.data.edges;
                network = drawGraph(in_nodes, in_edges);
                if (network) {
                    network.on('click', function (params) {
                        if (params.nodes.length != 0) {
                            var nodeID = params.nodes[0];
                            if (nodeID) {
                                clickedNode = nodes.get(nodeID);
                            }
                            // content = clickedNode.id
                            info.content = clickedNode
                        }
                    })
                }
            });
        }
    }
});