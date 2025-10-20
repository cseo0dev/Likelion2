using System;
using System.Collections.Generic;
using UnityEngine;

[Serializable]
public class RoomPrefabInfo
{
    public int Id;
    public GameObject Prefab;
}

public class RoomManager : MonoBehaviour
{
    [SerializeField] private List<RoomPrefabInfo> roomPrefabs;

    private Dictionary<int, Room> rooms;
    private Room currentRoom;

    private static RoomManager _instance;
    public static RoomManager Instance
    {
        get
        {
            if (_instance == null)
            {
                _instance = FindFirstObjectByType<RoomManager>();
                if (_instance == null)
                {
                    // TODO : 오류 처리
                }
            }
            return _instance;
        }
    }

    void Awake()
    {
        Room room0 = new Room(0);
        Room room1 = new Room(1);
        Room room2 = new Room(2);
        Room room3 = new Room(3);
        Room room4 = new Room(4);

        room0.AddNeighbor(room1);

        room1.AddNeighbor(room2);
        room1.AddNeighbor(room3);

        room2.AddNeighbor(room1);
        room2.AddNeighbor(room4);

        room3.AddNeighbor(room1);
        room3.AddNeighbor(room4);

        room4.AddNeighbor(room2);
        room4.AddNeighbor(room3);

        rooms = new Dictionary<int, Room>
        {
            {0, room0},
            {1, room1},
            {2, room2},
            {3, room3},
            {4, room4},
        };
    }

    void Start()
    {
        var startRoomId = 0;
        
        var prefab = GetRoomPrefab(startRoomId);
        if (prefab != null)
        {
            var instance = Instantiate(prefab);
            rooms[startRoomId].roomInstance = instance;
        }
    }

    public void SetNeighborsRoom(int id)
    {
        var room = rooms[id];
        if (room == null) return;

        foreach(var neighbor in room.Neighbors)
        {
            if (!neighbor.roomInstance)
            {
                var prefab = GetRoomPrefab(neighbor.Id);
                if(prefab != null)
                {
                    neighbor.roomInstance = Instantiate(prefab);
                }
            }
        }
    }

    private GameObject GetRoomPrefab(int id)
    {
        //foreach (var roomPrefab in roomPrefabs)
        //{
        //    if (roomPrefab.Id == id)
        //    {
        //        return roomPrefab.Prefab;
        //    }
        //}

        var prefab = roomPrefabs.Find(x => x.Id == id);
        return prefab != null ? prefab.Prefab : null;
    }
}
