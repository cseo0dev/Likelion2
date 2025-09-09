using System;
using System.Net.Sockets;
using Newtonsoft.Json;
using SocketIOClient;
using UnityEngine;

// joinRoom/createRoom �̺�Ʈ ������ �� ���޵Ǵ� ������ Ÿ��
public class RoomData
{
    [JsonProperty("roomId")]
    public string roomId { get; set; }
}

// ������ �� ��Ŀ ��ġ
public class BlockData
{
    [JsonProperty("blockIndex")]
    public int blockIndex { get; set; }
}

public class MultiplayController : IDisposable
{
    private SocketIOUnity _socket;

    private Action<Constants.MultiplayControllerState, string> _onMultiplayStateChanged; // Room ���� ��ȭ�� ���� ������ �Ҵ��ϴ� ����
    public Action<int> onBlockDataChanged; // ���� ���� ��Ȳ���� Marker�� ��ġ�� ������Ʈ �ϴ� ����

    public MultiplayController(Action<Constants.MultiplayControllerState, string> onMultiplayStateChanged)
    {
        // �������� �̺�Ʈ�� �߻��ϸ� ó���� �޼��带 _onMultiplayStateChanged�� ���
        _onMultiplayStateChanged = onMultiplayStateChanged;

        // Socket.io Ŭ���̾�Ʈ �ʱ�ȭ
        var uri = new Uri(Constants.SocketServerURL);
        _socket = new SocketIOUnity(uri, new SocketIOOptions
        {
            Transport = SocketIOClient.Transport.TransportProtocol.WebSocket,
            Reconnection = false,          // �ڵ� ������ ����
            ReconnectionAttempts = 0       // Ȥ�� �� �õ� �� 0
        });

        _socket.On("createRoom", CreateRoom);
        _socket.On("joinRoom", JoinRoom);
        _socket.On("startGame", StartGame);
        _socket.On("exitRoom", ExitRoom);
        _socket.On("endGame", EndGame);
        _socket.On("doOpponent", DoOpponent);
        _socket.Connect(); // ���� ����
    }

    private void CreateRoom(SocketIOResponse response)
    {
        var data = response.GetValue<RoomData>();

        UnityThread.executeInUpdate(() =>
        {
            _onMultiplayStateChanged?.Invoke(Constants.MultiplayControllerState.CreateRoom,
                data.roomId);
        });
    }

    private void JoinRoom(SocketIOResponse response)
    {
        var data = response.GetValue<RoomData>();
        UnityThread.executeInUpdate(() =>
        {
            _onMultiplayStateChanged?.Invoke(Constants.MultiplayControllerState.JoinRoom,
                data.roomId);
        });
    }

    private void StartGame(SocketIOResponse response)
    {
        var data = response.GetValue<RoomData>();
        UnityThread.executeInUpdate(() =>
        {
            _onMultiplayStateChanged?.Invoke(Constants.MultiplayControllerState.StartGame,
                data.roomId);
        });
    }

    private void ExitRoom(SocketIOResponse response)
    {
        UnityThread.executeInUpdate(() =>
        {
            _onMultiplayStateChanged?.Invoke(Constants.MultiplayControllerState.ExitRoom, null);
        });
    }

    private void EndGame(SocketIOResponse response)
    {
        UnityThread.executeInUpdate(() =>
        {
            _onMultiplayStateChanged?.Invoke(Constants.MultiplayControllerState.EndGame, null);
        });
    }

    private void DoOpponent(SocketIOResponse response)
    {
        var data = response.GetValue<BlockData>();
        UnityThread.executeInUpdate(() =>
        {
            onBlockDataChanged?.Invoke(data.blockIndex);
        });
    }

    #region Client => Server
    public void LeaveRoom(string roomId) // Room�� ���� �� ȣ���ϴ� �޼���
    {
        _socket.Emit("leaveRoom", new { roomId });
    }

    public void DoPlayer(string roomId, int blockIndex) // �÷��̾ Marker�� �θ� ȣ���ϴ� �޼���
    {
        _socket.Emit("doPlayer", new { roomId, blockIndex });
    }
    #endregion

    public void Dispose()
    {
        if (_socket != null)
        {
            _socket.Disconnect(); // ���� ���� ����
            _socket.Dispose(); // ���� ����
            _socket = null;
        }
    }
}