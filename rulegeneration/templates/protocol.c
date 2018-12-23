// $NAME
if (data + offset + sizeof(*$STRUCT_NAME) > data_end){
    $NO_DATA;
} else {
    $STRUCT_NAME = data + offset;
    offset += $SIZE;
    proto$NEXT_OSI = $PROTOCOL;
}