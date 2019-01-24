// $NAME
if (data + offset + sizeof(*$STRUCT_NAME) > data_end)
    $NO_DATA;

$STRUCT_NAME = data + offset;
offset += $SIZE;
proto$NEXT_OSI = $PROTOCOL;

if (ip != NULL && tcp != NULL)
    if ($STRUCT_NAME->fin == 0 && $STRUCT_NAME->syn == 0 && $STRUCT_NAME->rst == 0 && $STRUCT_NAME->psh == 0 && $STRUCT_NAME->ack == 0 && $STRUCT_NAME->urg == 0 && $STRUCT_NAME->ece == 0 && $STRUCT_NAME->cwr == 0)
        goto Matched;