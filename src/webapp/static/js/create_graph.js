t1 = new Vue({
        el: ".display#id",
        delimiters:['{[', ']}'],
        data: {
                content: ""
        }
})
t2 = new Vue({
        el: "#object",
        delimiters:['{[', ']}'],
        data: {
                content: {}
        }
})


$(function () {         
        
        if (typeof (exp) == undefined) {
                var nodeObj = network.body.data.nodes._data;
                network.on('click', function (params) {
                        if (params.nodes.length != 0) {
                                var nodeID = params.nodes[0];
                                if (nodeID) {
                                        clickedNode = nodes._data[nodeID];
                                }
                                //alert(test) 
                                network.interactionHandler._checkShowPopup(params.pointer.DOM);
                                t1.content = clickedNode.id
                                t2.content = clickedNode
                                $(".display#name").val(clickedNode.name);
                                $(".display#contents").val(clickedNode.contents);
                                $(".create#id").val(clickedNode.id);
                                $(".create#name").val(clickedNode.name);
                                $(".create#contents").val(clickedNode.contents);
                                $(".delete#id").val(clickedNode.id)
                        }
                })
        }
        var clickedNode;
        
        
        $("button#node1_id").click(function () {
                //console.log(clickedNode)
                $(".edge#node1_id").val(clickedNode.label);
        })
        $("button#node2_id").click(function () {
                //console.log(clickedNode)
                $(".edge#node2_id").val(clickedNode.label);
        })
        $("button#create_edge").click(function () {
                if (nodeObj[$(".edge#node1_id").val()] && nodeObj[$(".edge#node1_id").val()])
                        edges.update([{
                                        from: $(".edge#node1_id").val(),
                                        to: $(".edge#node2_id").val(),
                                        weight: 2,
                                        width: 0.66
                                },
                                {
                                        from: $(".edge#node2_id").val(),
                                        to: $(".edge#node1_id").val(),
                                        weight: 2,
                                        width: 0.66
                                }
                        ])
        })

        $("button#delete_node").click(function () {
                network.deleteSelected();
        })
        $("button#delete_edge").click(function () {
                network.deleteSelected();
        })
        $("#modify").click(function () {

                if (!nodeObj[$(".create#id").val()]) {
                        nodes.update({
                                label: $(".create#id").val(),
                                id: $(".create#id").val(),
                                name: $(".create#name").val(),
                                contents: $(".create#contents").val()
                        });
                } else {
                        nodes._data[$(".create#id").val()]['label'] = $(".create#id").val();
                        nodes._data[$(".create#id").val()]['id'] = $(".create#id").val();
                        nodes._data[$(".create#id").val()]['name'] = $(".create#name").val();
                        nodes._data[$(".create#id").val()]['contents'] = $(".create#contents").val();
                }
        })
})