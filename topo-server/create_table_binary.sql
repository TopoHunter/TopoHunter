/*==============================================================*/
/* DBMS name:      MySQL 5.0                                    */
/* Created on:     2022/12/6 13:05:40                           */
/*==============================================================*/

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
   host_id              tinyint unsigned not null,
   primary key (node_addr),
   INDEX idx_node_opr_host (opr_id, host_id)
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
   host_id              tinyint unsigned not null,
   primary key (src_addr, dst_addr),
   INDEX idx_edge_opr_host (opr_id, host_id)
);