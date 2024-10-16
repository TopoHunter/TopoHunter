drop table if exists Edge;

drop table if exists Node;

/*==============================================================*/
/* Table: Node                                                  */
/*==============================================================*/
create table Node
(
   node_addr            binary(17) not null,
   target_addr          binary(17) not null,
   discovered_time      int unsigned not null,
   opr_id               smallint unsigned not null,
   primary key (node_addr),
   INDEX idx_node_opr (opr_id)
);

/*==============================================================*/
/* Table: Edge                                                  */
/*==============================================================*/
create table Edge
(
   src_addr             binary(17) not null,
   dst_addr             binary(17) not null,
   hop_distance         tinyint unsigned not null,
   target_addr          binary(17) not null,
   discovered_time      int unsigned not null,
   opr_id               smallint unsigned not null,
   primary key (src_addr, dst_addr),
   INDEX idx_edge_opr (opr_id)
);
