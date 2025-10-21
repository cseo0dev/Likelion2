using System.Collections.Generic;
using UnityEngine;

public class Room
{
    public int Id { get; private set; }                 // ·ë ID
    public List<Room> Neighbors { get; private set; }   // ÁÖº¯ ·ë
    public GameObject roomInstance;                     // ¾À¿¡ »ý¼ºµÈ ·ë ¸ðµ¨

    public Room(int id)
    {
        roomInstance = null;
        Id = id;
        Neighbors = new List<Room>();
    }

    public void AddNeighbor(Room room)
    {
        if (!Neighbors.Contains(room))
        {
            Neighbors.Add(room);
            room.AddNeighbor(this);
        }
    }

    public void RemoveNeighbor(Room room)
    {
        if (Neighbors.Contains(room))
        {
            Neighbors.Remove(room);
            room.Neighbors.Remove(this);
        }
    }
}